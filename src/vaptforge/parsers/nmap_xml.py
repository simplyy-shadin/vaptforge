from __future__ import annotations

from defusedxml import ElementTree as ET

from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity


def parse_nmap_xml(xml_text: str, *, target: str) -> list[Finding]:
    root = ET.fromstring(xml_text)
    findings: list[Finding] = []

    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        host = address_node.get("addr") if address_node is not None else target
        ports_node = host_node.find("ports")
        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue

            service_node = port_node.find("service")
            port = int(port_node.get("portid", "0"))
            protocol = port_node.get("protocol", "tcp")
            service_name = service_node.get("name") if service_node is not None else None
            product = service_node.get("product") if service_node is not None else None
            version = service_node.get("version") if service_node is not None else None
            method = service_node.get("method") if service_node is not None else None
            confidence = service_node.get("conf") if service_node is not None else None

            # A name from Nmap's services table is only a port-based hint. Treat the
            # service as identified when probing produced a result or when Nmap
            # supplied a concrete product fingerprint.
            service_identified = bool(product or method == "probed")
            verified_service = service_name if service_identified else None
            product_version = " ".join(part for part in [product, version] if part)

            if service_identified:
                display = product_version or service_name or "unknown service"
                title = (
                    f"Open {protocol.upper()} port {port} "
                    f"({service_name or 'identified service'})"
                )
                description = f"Nmap identified an open service: {display}."
                evidence_summary = (
                    f"{protocol}/{port} open; service={display}; "
                    f"method={method or 'unspecified'}; confidence={confidence or 'unknown'}"
                )
            elif service_name:
                title = f"Open {protocol.upper()} port {port}"
                description = (
                    "Nmap identified an open port. Its service table suggests "
                    f"'{service_name}', but that is not a verified service identification."
                )
                evidence_summary = (
                    f"{protocol}/{port} open; service_hint={service_name}; "
                    f"method={method or 'table'}; confidence={confidence or 'unknown'}"
                )
            else:
                title = f"Open {protocol.upper()} port {port}"
                description = "Nmap identified an open port; the service was not identified."
                evidence_summary = f"{protocol}/{port} open; service=unknown"

            findings.append(
                Finding(
                    title=title,
                    severity=Severity.INFO,
                    asset=AssetRef(
                        target=target,
                        host=host,
                        port=port,
                        protocol=protocol,
                        service=verified_service,
                    ),
                    source="nmap",
                    description=description,
                    location=f"{host}:{port}",
                    evidence=[
                        Evidence(
                            source="nmap",
                            summary=evidence_summary,
                        )
                    ],
                    tags=["network-exposure"],
                    metadata={
                        "product": product,
                        "version": version,
                        "service_name": service_name,
                        "service_method": method,
                        "service_confidence": confidence,
                        "service_identified": service_identified,
                    },
                )
            )
    return findings
