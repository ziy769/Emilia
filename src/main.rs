use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use native_tls::TlsConnector;
use serde_json::Value;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_RESOLVER: &str = "/meta";
const PROXY_FILE: &str = "Data/ProxyIsp.txt";
const OUTPUT_FILE: &str = "Data/alive.txt";
const MAX_CONCURRENT: usize = 75;
const TIMEOUT_SECONDS: u64 = 5;

// Define a custom error type that implements Send + Sync
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting proxy scanner...");
    
    // Create output directory if it doesn't exist
    if let Some(parent) = Path::new(OUTPUT_FILE).parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Clear output file before starting
    File::create(OUTPUT_FILE)?;
    println!("File {} has been cleared before scanning process started.", OUTPUT_FILE);
    
    // Read proxy list from file
    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };
    
    println!("Loaded {} proxies from file", proxies.len());
    
    // Get original IP (without proxy)
    let original_ip_data = match check_connection(IP_RESOLVER, PATH_RESOLVER, None).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to get original IP info: {}", e);
            return Err(e.into());
        }
    };
    
    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("Failed to extract original client IP");
            return Err("Failed to extract original client IP".into());
        }
    };
    
    println!("Original IP: {}", original_ip);
    
    // Store active proxies
    let active_proxies = Arc::new(Mutex::new(Vec::new()));
    
    // Process proxies concurrently
    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            
            async move {
                process_proxy(proxy_line, &original_ip, &active_proxies).await;
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();
    
    tasks.await;
    
    // Save active proxies to file
    let active_proxies = active_proxies.lock().unwrap();
    if !active_proxies.is_empty() {
        let mut file = File::create(OUTPUT_FILE)?;
        for proxy in active_proxies.iter() {
            writeln!(file, "{}", proxy)?;
        }
        println!("All active proxies saved to {}", OUTPUT_FILE);
    } else {
        println!("No active proxies found");
    }
    
    println!("Proxy checking completed.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            proxies.push(line);
        }
    }
    
    Ok(proxies)
}

async fn check_connection(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>
) -> Result<Value> {
    let host = host.to_string();
    let path = path.to_string();
    let proxy = proxy.map(|(ip, port)| (ip.to_string(), port));
    
    // Use spawn_blocking to run the blocking SSL connection in a separate thread
    tokio::task::spawn_blocking(move || {
        check_connection_sync(&host, &path, proxy.as_ref().map(|(ip, port)| (ip.as_str(), *port)))
    }).await?
}

fn check_connection_sync(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>
) -> Result<Value> {
    // Build HTTP request payload
    let payload = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n\
         Connection: close\r\n\r\n",
        path, host
    );
    
    // Create TCP connection
    let stream = if let Some((proxy_ip, proxy_port)) = proxy {
        // Connect to proxy
        TcpStream::connect_timeout(
            &format!("{}:{}", proxy_ip, proxy_port).parse()?,
            Duration::from_secs(TIMEOUT_SECONDS)
        )?
    } else {
        // Connect directly to host (with DNS resolution)
        let socket_addr = format!("{}:443", host)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not resolve hostname"))?;
        
        TcpStream::connect_timeout(
            &socket_addr,
            Duration::from_secs(TIMEOUT_SECONDS)
        )?
    };
    
    stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))?;
    stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))?;
    
    // Create TLS connection
    let connector = TlsConnector::new()?;
    let mut tls_stream = connector.connect(host, stream)?;
    
    // Send HTTP request
    tls_stream.write_all(payload.as_bytes())?;
    
    // Read response
    let mut response = Vec::new();
    let mut buffer = [0; 4096];
    
    loop {
        match tls_stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }
    }
    
    // Parse response
    let response_str = String::from_utf8_lossy(&response);
    
    // Split headers and body
    if let Some(body_start) = response_str.find("\r\n\r\n") {
        let body = &response_str[body_start + 4..];
        
        // Try to parse the JSON body
        match serde_json::from_str::<Value>(body.trim()) {
            Ok(json_data) => Ok(json_data),
            Err(e) => {
                // If JSON parsing fails, print the response for debugging
                eprintln!("Failed to parse JSON: {}", e);
                eprintln!("Response body: {}", body);
                Err("Invalid JSON response".into())
            }
        }
    } else {
        Err("Invalid HTTP response".into())
    }
}

fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect()
}

async fn process_proxy(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<String>>>
) {
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 4 {
        println!("Invalid proxy line format: {}. Make sure it's ip,port,country,org", proxy_line);
        return;
    }
    
    let ip = parts[0];
    let port = parts[1];
    let country = parts[2];
    let org = parts[3];
    
    let port_num = match port.parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid port number: {}", port);
            return;
        }
    };
    
    match check_connection(IP_RESOLVER, PATH_RESOLVER, Some((ip, port_num))).await {
        Ok(proxy_data) => {
            if let Some(Value::String(proxy_ip)) = proxy_data.get("clientIp") {
                if proxy_ip != original_ip {
                    let org_name = if let Some(Value::String(org_name)) = proxy_data.get("asOrganization") {
                        clean_org_name(org_name)
                    } else {
                        org.to_string()  // Use the original org if not available in response
                    };
                    
                    let proxy_entry = format!("{},{},{},{}", ip, port, country, org_name);
                    println!("CF PROXY LIVE!: {}", proxy_entry);
                    
                    let mut active_proxies = active_proxies.lock().unwrap();
                    active_proxies.push(proxy_entry);
                } else {
                    println!("CF PROXY DEAD! (Same IP): {}:{}", ip, port);
                }
            } else {
                println!("CF PROXY DEAD! (No client IP): {}:{}", ip, port);
            }
        },
        Err(e) => {
            println!("CF PROXY DEAD! (Error): {}:{} - {}", ip, port, e);
        }
    }
}
