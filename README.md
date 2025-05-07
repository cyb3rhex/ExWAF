# ExWAF - Exchange Web Application Firewall

ExWAF is a lightweight, purpose-built web application firewall designed specifically to protect Microsoft Exchange Outlook Web Access (OWA) servers from common web attacks. It acts as a reverse proxy, inspecting requests for attack patterns, sanitizing inputs, applying rate limiting, blocking malicious IPs, and logging activity.

## Features

- **Purpose-built for Exchange OWA**: Designed specifically to protect Exchange OWA 2019 servers
- **Input Sanitization**: Detects and neutralizes XSS, SQL injection, and other common attack vectors
- **Rate Limiting**: Protects against brute force and credential stuffing attacks
- **IP Blocking**: Automatically blocks IPs showing malicious activity patterns
- **Security Headers**: Enforces secure headers to improve overall security posture
- **Real-time Monitoring**: Dashboard for tracking WAF activity and threats
- **Low Performance Impact**: Lightweight design minimizes impact on server performance

## Quick Start

### Prerequisites

- Windows Server with IIS (running Exchange OWA)
- Python 3.10 or higher
- Administrator privileges

### Installation

1. Clone or download this repository to your Exchange server
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the IIS setup script (requires administrator privileges):
   ```powershell
   .\setup_IIS.ps1 -WafIp "127.0.0.1" -WafPort 8080 -ExchangeServer "localhost" -ExchangePort 443
   ```
4. Start the WAF and Dashboard:
   ```
   start_ExWAF.bat
   start_Dashboard.bat
   ```

### Configuration

The main configuration is handled by the setup script. For advanced customization:

1. Edit `ExWAF.py` to modify security patterns or proxy behavior
2. Access the dashboard at http://localhost:8081 for real-time monitoring

## Architecture

ExWAF operates as a reverse proxy with the following flow:

1. Client browser connects to IIS on port 443 (HTTPS)
2. IIS URL Rewrite forwards traffic to ExWAF on port 8080 (local HTTP)
3. ExWAF inspects requests, applies security rules, and forwards clean traffic to Exchange
4. Exchange OWA processes the request and sends response back through the proxy chain

```
[Client] <-> HTTPS <-> [IIS] <-> HTTP <-> [ExWAF] <-> HTTP <-> [Exchange OWA]
```

## Best Practices

- Regularly update attack patterns
- Monitor the dashboard for suspicious activity
- Tune rate limiting based on normal usage patterns
- Keep ExWAF updated with the latest security patterns
- Use ExWAF alongside other security measures like firewalls

## License

Copyright (c) 2025. All rights reserved.

## Support

For questions or issues, please open an issue on the repository. 