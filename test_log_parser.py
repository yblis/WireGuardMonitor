from log_parser import WireGuardLogParser

def test_parser():
    parser = WireGuardLogParser()
    
    # Test cases for different log formats
    test_logs = [
        # Standard WireGuard log
        'peer AbCdEfGh12345678= (192.168.1.2): connection established',
        
        # Docker format log
        '[2024-10-29 20:15:30] wireguard[123]: peer BcDeFgHi87654321= (10.0.0.2): connection established',
        
        # Docker with container ID
        'Oct 29 20:15:35 container_id=abc123def456 wireguard: peer CdEfGhIj76543210= (172.16.0.2): connection established',
        
        # Transfer stats in Docker format
        '[2024-10-29 20:15:40] wireguard[124]: peer AbCdEfGh12345678=: tx: 1234 B, rx: 5678 B',
        
        # Disconnection in Docker format
        '[2024-10-29 20:15:45] wireguard[125]: peer BcDeFgHi87654321= (10.0.0.2): disconnected'
    ]
    
    print("Testing WireGuard log parser with Docker support:")
    print("-" * 50)
    
    for log_line in test_logs:
        result = parser.parse_line(log_line)
        if result:
            print(f"\nParsed log line: {log_line}")
            print(f"Result: {result}")
        else:
            print(f"\nFailed to parse: {log_line}")

if __name__ == "__main__":
    test_parser()
