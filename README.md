# GCP Port Scanner

A **parallel port scanner** that scans external IPs of GCP VMs, GKE Nodes, LoadBalancer Services, and Reserved IPs.  
The script efficiently discovers open ports using **multi-threading** and saves results in a CSV file.

## 🚀 Features
- ✅ **Scans all external IPs** from:
  - GCP Virtual Machines (VMs)
  - GKE LoadBalancer services
  - GKE Nodes with external IPs
  - Reserved GCP IPs
- ✅ **Multithreaded scanning** for high performance
- ✅ **Filters out private IPs (`10.x.x.x`)**
- ✅ **Outputs results to `scan_results.csv`**
- ✅ **Customizable port selection**

---

## 📦 Installation
1. **Clone the repository**
```bash
   Ensure you have gcloud setup. 

   gcloud auth application-default login
   gcloud config set project <YOUR_PROJECT_ID>
   kubectl config use-context <YOUR_CLUSTER_CONTEXT>

```