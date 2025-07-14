# **Arista Configuration Anonymizer**

## **Overview**

This Python script is a command-line tool designed to anonymize sensitive information within Arista switch configuration files. It reads a configuration from standard input, masks specified data based on command-line flags, and prints the sanitized configuration to standard output.  
Script provided as-is. Please review before using this script.

## **Features**

* **IP Address Masking**: Automatically masks the first two octets of IPv4 addresses (e.g., 192.168.1.1 becomes x.x.1.1) and the first two blocks of IPv6 addresses (e.g., 2001:db8:a:b::1 becomes y:y:a:b::1).  
* **Intelligent RD Handling**: Correctly masks IP addresses within Route Distinguisher (RD) values (e.g., rd 192.168.100.1:100) while leaving AS-based RDs (rd 65001:200) untouched.  
* **Optional VRF Masking**: (Enabled with \-vrfname) Discovers all VRF definitions and replaces every occurrence of the VRF name with a generic, sequenced name (e.g., CUST-RED becomes vrf\_1). This applies to all configuration sections, including interface, router bgp, and vxlan vrf commands.  
* **Optional Description Masking**: (Enabled with \-desc) Replaces the text in any description line with \<description removed\>.  
* **Optional Comment Masking**: (Enabled with \-comment) Replaces the text on any comment line (lines beginning with \! ) with \<comment removed\>.

## **Requirements**

* Python 3.x

## **Usage**

The script is designed to be used in a pipeline, typically with cat to read the configuration file.  
cat /path/to/your/running-config.txt | ./arista\_anonymizer.py \[flags\]

### **Command-Line Flags**

The script's behavior is controlled by optional flags. You can use them individually or combine them.

* **No Flags** (Default Behavior): Masks only IPv4 and IPv6 addresses.  
  cat config.txt | ./arista\_anonymizer.py

* \-vrfname: Masks IP addresses AND all VRF names.  
  cat config.txt | ./arista\_anonymizer.py \-vrfname

* \-desc: Masks IP addresses AND description text.  
  cat config.txt | ./arista\_anonymizer.py \-desc

* \-comment: Masks IP addresses AND comment text.  
  cat config.txt | ./arista\_anonymizer.py \-comment

* **Combined Flags**: All flags can be used together to perform maximum anonymization.  
  cat config.txt | ./arista\_anonymizer.py \-vrfname \-desc \-comment

## **Example**

### **Original Configuration (running-config.txt)**

\! This is a sensitive configuration for the core router.  
vrf definition CUST-RED  
   description Link to customer A  
   rd 192.168.100.1:100  
\!  
interface Ethernet1  
   description Management  
   ip address 10.1.1.1/24  
\!  
interface Vxlan1  
   vxlan vrf CUST-RED vni 10100

### **Anonymized Output**

Running the script with all flags:  
cat running-config.txt | ./arista\_anonymizer.py \-vrfname \-desc \-comment  
\! \<comment removed\>  
vrf definition vrf\_1  
   description \<description removed\>  
   rd x.x.100.1:100  
\!  
interface Ethernet1  
   description \<description removed\>  
   ip address x.x.1.1/24  
\!  
interface Vxlan1  
   vxlan vrf vrf\_1 vni 10100  
