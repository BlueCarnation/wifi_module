use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::time::Instant;
use tokio_wifiscanner;
use csv;

#[derive(Serialize)]
struct WifiData {
    ssid: String,
    mac: String,
    manufacturer: Option<String>,
    network_security: String,
    channel: i32,
}

#[derive(Deserialize)]
struct Config {
    instant_scan: bool,
    start_after_duration: Option<u64>,
    scan_duration: Option<u64>,
}

#[tokio::main]
async fn main() {
    match run_wifi_script().await {
        Ok(result) => {
            if result {
                println!("WiFi data script executed successfully.");
            } else {
                println!("No data was processed.");
            }
        }
        Err(e) => println!("Error occurred: {}", e),
    }
}


pub async fn run_wifi_script() -> Result<bool, Box<dyn std::error::Error>> {
    // Open and Read the configuration file
    let mut file = File::open("config.json").expect("Cannot open config.json");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Cannot read config.json");
    let config: Config = serde_json::from_str(&contents).expect("Cannot parse JSON");

    if config.instant_scan {
        println!("\nScan was set to be instant, starting scan...");


        let networks = scan().await?;

        // Read the Organizationally Unique Identifier (oui) CSV file
        let oui_data = read_oui_csv("src/database/oui.csv")?;

        // Convert the WiFi data to JSON
        let wifi_data = convert_to_wifi_data(&networks, &oui_data);

        // Nouvelle structure de données pour le format JSON
        let mut formatted_wifi_data = serde_json::Map::new();

        // Itérer sur les données WiFi et les ajouter dans le nouveau format
        for (i, data) in wifi_data.iter().enumerate() {
            // Clé sous forme de chaîne ("1", "2", etc.)
            let key = (i + 1).to_string();
            // Ajouter l'objet data sous la clé correspondante
            formatted_wifi_data.insert(key, serde_json::to_value(data)?);
        }

        // Sérialiser et écrire les données dans le nouveau format
        let json_data = serde_json::to_string_pretty(&formatted_wifi_data)?;

        println!("{}", json_data);

        write_json_to_file(&json_data, "wifi_instantdata.json")?;

        if json_data == "{}" {
            Ok(false)
        } else {
            Ok(true)
        }
    } else {
        println!("\nScan was set to be delayed");

        let oui_data = read_oui_csv("src/database/oui.csv")?;

        // Configuration pour un scan différé basé sur le fichier config.json
        let start_after_duration = config.start_after_duration.unwrap_or(0);
        let scan_duration = config.scan_duration.unwrap_or(60); // Durée par défaut de 60 secondes

        for i in (1..=start_after_duration).rev() {
            println!("Scan starts in {} seconds", i);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        println!("Scan started, it will last for {} seconds...", scan_duration);
        let scan_start_time = Instant::now();
        let mut last_seen: HashMap<String, Instant> = HashMap::new();

        let mut device_intervals: HashMap<String, Vec<(Instant, Instant)>> = HashMap::new();
        let mut last_seen: HashMap<String, Instant> = HashMap::new();

        let mut networks = Vec::new();

        while Instant::now().duration_since(scan_start_time) < tokio::time::Duration::from_secs(scan_duration) {
            networks = scan().await?;

            for network in networks.iter() {
                let now = Instant::now();
                let device_id = &network.mac;

                let device_last_seen = last_seen.entry(device_id.clone()).or_insert(now);

                if now.duration_since(*device_last_seen).as_secs() > 5 {
                    // Nouvel intervalle si plus de 5 secondes se sont écoulées depuis la dernière détection
                    if let Some(intervals) = device_intervals.get_mut(device_id) {
                        intervals.push((*device_last_seen, now));
                    } else {
                        device_intervals.insert(device_id.clone(), vec![(*device_last_seen, now)]);
                    }
                }

                *device_last_seen = now;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        // Convertir les intervalles en durées et collecter les données finales pour chaque appareil
        let mut results: Vec<Value> = vec![];
        for (mac, intervals) in device_intervals.iter() {
            let durations = intervals.iter()
                .map(|(start, end)| end.duration_since(*start).as_secs())
                .collect::<Vec<u64>>();

            // Trouver la première occurrence du réseau pour obtenir les données
            if let Some(first_network) = networks.iter().find(|n| n.mac == *mac) {
                let manufacturer = get_manufacturer(&first_network.mac, &oui_data);

                let data = json!({
                    "ssid": first_network.ssid,
                    "mac": first_network.mac,
                    "manufacturer": manufacturer,
                    "network_security": if first_network.security.is_empty() { "Open" } else { "Secured" },
                    "channel": first_network.channel,
                    "wifi_durations": durations,
                });

                results.push(data);
            }
        }

        let json_data = serde_json::to_string_pretty(&results)?;
        println!("{}", json_data);
        write_json_to_file(&json_data, "wifi_scheduleddata.json")?;

        Ok(true)
    }
}

fn convert_to_wifi_data(networks: &[tokio_wifiscanner::Wifi], oui_data: &HashMap<String, String>) -> Vec<serde_json::Value> {
    let mut wifi_data = Vec::new();

    for network in networks {
        let manufacturer = get_manufacturer(&network.mac, oui_data);
        let network_security = if network.security.is_empty() { "1" } else { "0" };
        let ssid_sanitized = network.ssid.replace("'", " ");
        let wifi_data_item = serde_json::to_value(WifiData {
            ssid: if ssid_sanitized.is_empty() { "none".to_string() } else { ssid_sanitized },
            mac: if network.mac.is_empty() { "none".to_string() } else { network.mac.clone() },
            manufacturer,
            network_security: network_security.to_string(),
            channel: network.channel.parse().unwrap_or(0),
        })
        .unwrap();
        wifi_data.push(wifi_data_item);
    }

    wifi_data
}

fn get_manufacturer(mac: &str, oui_data: &HashMap<String, String>) -> Option<String> {
    // Get the first three octets of the MAC address
    let mac_prefix = mac.split(':').take(3).collect::<String>().to_uppercase();
    match oui_data.get(&mac_prefix) {
        Some(manufacturer) => Some(manufacturer.clone()),
        None => Some("Unknown".to_string()),
    }
}

fn write_json_to_file(json_data: &str, filename: &str) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

fn read_oui_csv(filename: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut oui_data = HashMap::new();
    let mut rdr = csv::Reader::from_path(filename)?;

    for result in rdr.records() {
        let record = result?;
        // Check if the record contains at least three elements
        if record.len() >= 3 {
            let mac_prefix = record.get(1).unwrap();
            let manufacturer = record.get(2).unwrap();
            // Insert the manufacturer into the HashMap
            oui_data.insert(mac_prefix.to_uppercase(), manufacturer.to_string());
        }
    }

    // return the HashMap
    Ok(oui_data)
}

async fn scan() -> Result<Vec<tokio_wifiscanner::Wifi>, tokio_wifiscanner::Error> {
    tokio_wifiscanner::scan().await
}
