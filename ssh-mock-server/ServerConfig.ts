export interface ServerConfig {
    // listening port
    port: number;
    // default kex algorithm
    kex_algorithms: string;
    server_host_key_algorithms: string;
    encryption_algorithms_client_to_server: string;
    encryption_algorithms_server_to_client: string;
    mac_algorithms_client_to_server: string;
    mac_algorithms_server_to_client: string;
    compression_algorithms_client_to_server: string;
    compression_algorithms_server_to_client: string;
}