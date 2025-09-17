<table>
  <tr>
    <td width="50%">
      <img src="Assets/IP%20Change.gif" alt="IP Location Change" width="100%">
    </td>
    <td width="50%">
      <img src="Assets/Speed.gif" alt="Speed Test" width="100%">
    </td>
  </tr>
</table>

# EC2 VPN

A custom VPN implementation built from scratch that routes internet traffic through an AWS EC2 instance (t4g.nano costing $3.04/month). The .exe is a standalone Windows 10/11 client that auto-configures and connects to the VPN server with a single click. hTe VPN uses AES-256-GCM encryption. This was created fully with python + tkinter for the GUI. The server is deployed through a GitHub Actions CI/CD pipeline that builds and deploys a Docker container to the EC2 instance on every push to main.

## Features

- **Auto Setup** - One-click activation of VPN on Windows 10/11 client machines
- **IP Address Masking** - Routes all traffic through AWS EC2 instance to hide real location
- **Encryption** - AES-256-GCM encryption with perfect forward secrecy
- **High Performance** - Achieves 95% of native connection speed with <10ms latency overhead
- **DNS Leak Protection** - Prevents DNS queries from bypassing the VPN tunnel
- **Auto-Reconnection** - Automatically reconnects on connection drops with exponential backoff
- **Zero Logs** - No traffic or connection logs stored

## Technologies

<div align="center">

![Python](https://img.shields.io/badge/python-00ADD8?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS_EC2-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

</div>

---

### 📦 **Download Latest Release**

> **Ready to use Windows binary is available in the [Releases](https://github.com/yourusername/securetunnel-vpn/releases) section**
>
> Download `vpn-client-windows.exe` for Windows 10/11

---

## Deployment

To deploy your own instance, fork this repository and set up the automated deployment pipeline. First, configure your AWS credentials as GitHub secrets in your forked repository settings: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_EC2_INSTANCE_IP`. The included GitHub Actions workflow will automatically build and deploy the VPN server to your Linux EC2 instance on every push to main. Simply fork the repo, add your AWS secrets, and push a commit to trigger the deployment. The server will be containerized and deployed with all necessary networking configurations, ready to accept Windows client connections on port 51820.
