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
    wifi_durations: String,  
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
    let mut file = File::open("config.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = serde_json::from_str(&contents)?;

    if config.instant_scan {
        println!("\nScan was set to be instant, starting scan...");
        let networks = scan().await?;
        let oui_data = read_oui_csv("src/database/oui.csv")?;
        let wifi_data = convert_to_wifi_data(&networks, &oui_data);

        let mut formatted_wifi_data = serde_json::Map::new();
        for (i, data) in wifi_data.iter().enumerate() {
            let key = (i + 1).to_string();
            formatted_wifi_data.insert(key, serde_json::to_value(data)?);
        }

        let json_data = serde_json::to_string_pretty(&formatted_wifi_data)?;
        println!("{}", json_data);
        write_json_to_file(&json_data, "wifi_instantdata.json")?;
        Ok(!json_data.is_empty())
    } else {
        println!("\nScan was set to be delayed");
        let oui_data = read_oui_csv("src/database/oui.csv")?;
        let start_after_duration = config.start_after_duration.unwrap_or(0);
        let scan_duration = config.scan_duration.unwrap_or(60);
        for i in (1..=start_after_duration).rev() {
            println!("Scan starts in {} seconds", i);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        println!("Scan started, it will last for {} seconds...", scan_duration);
        let scan_start_time = Instant::now();
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

    // Generate ID-ed results based on device_intervals
    let mut formatted_wifi_data = serde_json::Map::new();
    let mut id = 1;
    for (mac, intervals) in &device_intervals {
        let durations = intervals.iter()
            .map(|(start, end)| format!("{}-{}", start.elapsed().as_secs(), end.elapsed().as_secs()))
            .collect::<Vec<String>>().join(",");
        let network = networks.iter().find(|n| n.mac == *mac).unwrap(); // Safe unwrap because mac comes from scanned networks
        let manufacturer = get_manufacturer(&network.mac, &oui_data).unwrap_or_else(|| "Unknown".to_string());
        
        let wifi_data_item = json!({
            "ssid": sanitize_string(&network.ssid),
            "mac": network.mac,
            "manufacturer": manufacturer,
            "network_security": if network.security.is_empty() { "Open" } else { "Secured" },
            "channel": network.channel,
            "wifi_durations": durations
        });

        formatted_wifi_data.insert(id.to_string(), wifi_data_item);
        id += 1;
    }

    let json_data = serde_json::to_string_pretty(&formatted_wifi_data)?;
    println!("{}", json_data);
    write_json_to_file(&json_data, "wifi_scheduleddata.json")?;

    Ok(true)
    }
}

fn convert_to_wifi_data(networks: &[tokio_wifiscanner::Wifi], oui_data: &HashMap<String, String>) -> Vec<serde_json::Value> {
    networks.iter().map(|network| {
        let raw_manufacturer = get_manufacturer(&network.mac, oui_data).unwrap_or_else(|| "Unknown".to_string());
        let manufacturer = sanitize_string(&raw_manufacturer);
        let network_security = if network.security.is_empty() { "Open" } else { "Secured" };
        let ssid_sanitized = sanitize_string(&network.ssid);
        let wifi_data_item = json!({
            "ssid": ssid_sanitized,
            "mac": network.mac,
            "manufacturer": manufacturer,
            "network_security": network_security,
            "channel": network.channel,
            "wifi_durations": "" 
        });
        wifi_data_item
    }).collect()
}

fn sanitize_string(input: &str) -> String {
    input.replace("'", " ").replace("`", " ").replace("\"", " ")
}

fn get_manufacturer(mac: &str, oui_data: &HashMap<String, String>) -> Option<String> {
    let mac_prefix = mac.split(':').take(3).collect::<String>().to_uppercase();
    oui_data.get(&mac_prefix).cloned().or(Some("Unknown".to_string()))
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
        if record.len() >= 3 {
            let mac_prefix = record.get(1).unwrap();
            let manufacturer = record.get(2).unwrap();
            oui_data.insert(mac_prefix.to_uppercase(), manufacturer.to_string());
        }
    }
    Ok(oui_data)
}

async fn scan() -> Result<Vec<tokio_wifiscanner::Wifi>, tokio_wifiscanner::Error> {
    tokio_wifiscanner::scan().await
}

// Helper function to generate the final results
fn generate_results(
    device_intervals: &HashMap<String, Vec<(Instant, Instant)>>,
    networks: &[tokio_wifiscanner::Wifi],
    oui_data: &HashMap<String, String>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut results = serde_json::Map::new();
    for (mac, intervals) in device_intervals {
        let durations = intervals.iter()
            .map(|(start, end)| {
                // Ensure intervals are formatted from lower to higher time
                let start_secs = start.elapsed().as_secs();
                let end_secs = end.elapsed().as_secs();
                if start_secs <= end_secs {
                    format!("{}-{}", start_secs, end_secs)
                } else {
                    format!("{}-{}", end_secs, start_secs)
                }
            })
            .collect::<Vec<String>>().join(",");

        let first_network = networks.iter().find(|n| n.mac == *mac).unwrap();
        let manufacturer = get_manufacturer(&first_network.mac, oui_data).unwrap_or_else(|| "Unknown".to_string());
        let sanitized_manufacturer = sanitize_string(&manufacturer);

        let wifi_data_item = json!({
            "ssid": sanitize_string(&first_network.ssid),
            "mac": first_network.mac,
            "manufacturer": sanitized_manufacturer,
            "network_security": first_network.security,
            "channel": first_network.channel,
            "wifi_durations": durations
        });

        results.insert(mac.clone(), wifi_data_item);
    }
    results
}

