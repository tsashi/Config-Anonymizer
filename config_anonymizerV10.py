#!/usr/bin/env python3
"""
This script reads an Arista switch configuration from standard input,
anonymizes it, and prints the result to standard output.

Anonymization includes:
1. Masking IP addresses (IPv4 and IPv6), with special handling for Route
   Distinguishers (RDs).
2. Optionally, masking VRF names if the '-vrfname' flag is provided. When
   enabled, the script finds all 'vrf definition <name>' entries and
   replaces every occurrence of '<name>' throughout the configuration with a
   generic, sequenced name (e.g., vrf_1). This includes replacements in
   interface configurations, BGP stanzas, and VXLAN VNI mappings
   (e.g., 'vxlan vrf ...').
3. Optionally, masking text on 'description' lines if the '-desc' flag is
   provided.
4. Optionally, masking text on comment lines (starting with '!') if the
   '-comment' flag is provided.

Usage:
  - To mask IPs only: cat config.txt | ./this_script.py
  - To mask IPs and VRF names: cat config.txt | ./this_script.py -vrfname
  - To mask IPs, descriptions, and comments: cat config.txt | ./this_script.py -desc -comment
  - All flags can be used in conjunction.
"""
import sys
import re

# Regex to find IPv4 addresses.
ipv4_pattern = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

# A comprehensive, multi-line regex for matching valid IPv6 addresses,
# adapted from the Django framework for correctness and readability.
# This is used for validation with fullmatch().
ipv6_pattern = re.compile(
    r"("
    r"(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|"
    r"(?:[A-F0-9]{1,4}:){1,7}:|"
    r"(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}|"
    r"(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}|"
    r"(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}|"
    r"(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}|"
    r"(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}|"
    r"[A-F0-9]{1,4}:(?:(?::[A-F0-9]{1,4}){1,6})|"
    r":(?:(?::[A-F0-9]{1,4}){1,7}|:)|"
    r"fe80:(?::[A-F0-9]{0,4}){0,4}%[a-zA-Z0-9]{1,}|"
    r"::(?:ffff(?::0{1,4}){0,1}:){0,1}"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
    r"(?:[A-F0-9]{1,4}:){1,4}:"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r")",
    re.IGNORECASE,
)

# A simpler pattern for substitution to capture the first two groups of an IPv6 address.
ipv6_sub_pattern = re.compile(
    r"\b([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})(:[0-9a-fA-F:]*)?\b", re.IGNORECASE
)

# Regex to find VRF definitions in Arista configs (e.g., "vrf definition MGMT")
vrf_definition_pattern = re.compile(r"^\s*vrf definition (\S+)")


def replace_ips(line):
    """Replaces the first two octets of IPv4 and first two blocks of IPv6 addresses."""
    line = ipv4_pattern.sub(lambda m: f"x.x.{m.group(3)}.{m.group(4)}", line)
    line = ipv6_sub_pattern.sub(
        lambda m: f"y:y{m.group(3) if m.group(3) else ''}", line
    )
    return line


def process_line_for_text_masking(line, mask_desc, mask_comment):
    """Masks description and comment text if the respective flags are enabled."""
    if mask_desc:
        # Replaces 'description ...' with 'description <description removed>'
        line = re.sub(
            r"^(?P<indent>\s*)description .+",
            r"\g<indent>description <description removed>",
            line,
        )
    if mask_comment:
        # Replaces '! ...' with '! <comment removed>', ignoring lines with only '!'
        line = re.sub(r"^(?P<indent>\s*)! .+", r"\g<indent>! <comment removed>", line)
    return line


def process_line_for_ips(line):
    """
    Processes a single line for IP address masking, with special logic for 'rd' lines
    to prevent incorrect masking.
    """
    stripped_line = line.strip()
    if stripped_line.startswith("rd "):
        parts = stripped_line.split(None, 1)
        if len(parts) > 1:
            rd_value = parts[1]
            rd_parts = rd_value.rsplit(":", 1)
            if len(rd_parts) == 2:
                potential_ip_or_as = rd_parts[0]
                if ipv4_pattern.fullmatch(potential_ip_or_as):
                    return ipv4_pattern.sub(
                        lambda m: f"x.x.{m.group(3)}.{m.group(4)}", line
                    )
                elif ipv6_pattern.fullmatch(potential_ip_or_as):
                    return ipv6_sub_pattern.sub(
                        lambda m: f"y:y{m.group(3) if m.group(3) else ''}", line
                    )
                else:
                    return line
    return replace_ips(line)


def main():
    """
    Main function to orchestrate the anonymization process based on command-line arguments.
    """
    if sys.stdin.isatty():
        print("Error: No configuration data piped to the script.", file=sys.stderr)
        print(
            "Usage: cat your-config.txt | ./this_script.py [-vrfname] [-desc] [-comment]",
            file=sys.stderr,
        )
        sys.exit(1)

    # Check for command-line flags
    args = set(sys.argv[1:])
    mask_vrf_names = "-vrfname" in args
    mask_desc = "-desc" in args
    mask_comment = "-comment" in args

    if mask_vrf_names:
        # --- TWO-PASS LOGIC: MASK VRFs first, then other items ---
        config_lines = sys.stdin.readlines()
        vrf_map = {}
        vrf_counter = 1

        # PASS 1: Identify all VRF names
        for line in config_lines:
            match = vrf_definition_pattern.match(line)
            if match:
                original_vrf_name = match.group(1)
                if original_vrf_name not in vrf_map:
                    vrf_map[original_vrf_name] = f"vrf_{vrf_counter}"
                    vrf_counter += 1

        # PASS 2: Process each line for all replacements
        for line in config_lines:
            processed_line = line
            # A. Replace VRF names
            for original_vrf, masked_vrf in vrf_map.items():
                vrf_occurrence_pattern = re.compile(
                    r"\b" + re.escape(original_vrf) + r"\b"
                )
                processed_line = vrf_occurrence_pattern.sub(masked_vrf, processed_line)

            # B. Replace description/comment text
            processed_line = process_line_for_text_masking(
                processed_line, mask_desc, mask_comment
            )

            # C. Process for IP masking
            final_line = process_line_for_ips(processed_line)
            print(final_line, end="")
    else:
        # --- ONE-PASS LOGIC: No VRF masking needed ---
        for line in sys.stdin:
            # A. Replace description/comment text
            processed_line = process_line_for_text_masking(
                line, mask_desc, mask_comment
            )

            # B. Process for IP masking
            final_line = process_line_for_ips(processed_line)
            print(final_line, end="")
#

if __name__ == "__main__":
    main()
