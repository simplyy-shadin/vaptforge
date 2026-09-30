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
            service = service_node.get("name") if service_node is not None else None
            product = service_node.get("product") if service_node is not None else None
            version = service_node.get("version") if service_node is not None else None
            product_version = (
                " ".join(part for part in [product, version] if part)
                or service
                or "unknown"
            )

            findings.append(
                Finding(
                    title=f"Open {protocol.upper()} port {port} ({service or 'unknown service'})",
                    severity=Severity.INFO,
                    asset=AssetRef(
                        target=target,
                        host=host,
                        port=port,
                        protocol=protocol,
                        service=service,
                    ),
                    source="nmap",
                    description=f"Nmap identified an open service: {product_version}.",
                    location=f"{host}:{port}",
                    evidence=[
                        Evidence(
                            source="nmap",
                            summary=f"{protocol}/{port} open; service={product_version}",
                        )
                    ],
                    metadata={"product": product, "version": version},
                )
            )
    return findings
