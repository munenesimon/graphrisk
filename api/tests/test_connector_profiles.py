"""
Step 2 of the universal device profile: every connector that can see
devices maps them onto the same profile (see app/connectors/profile.py).
Offline tests per adapter -- CrowdStrike, Qualys, AWS (moto), Entra ID and
Okta are all verified against simulated APIs only, not live tenants -- plus
a contract test that holds every registered connector to the schema.
"""
import boto3
import responses
from moto import mock_aws
from responses import matchers

from app.connectors.adapters.aws import AWSAdapter
from app.connectors.adapters.crowdstrike import CrowdStrikeAdapter
from app.connectors.adapters.entra_id import EntraIDAdapter
from app.connectors.adapters.okta import OktaAdapter
from app.connectors.adapters.qualys import QualysAdapter
from app.connectors.profile import SECTIONS, normalize_profile
from app.connectors.registry import registry


def _assert_within_capability(adapter_cls, discovered):
    """What a connector reports must stay inside what it declares (anything
    outside the shared schema is fine -- it lands in "extra")."""
    for asset in discovered:
        sections = set(normalize_profile(asset.get("profile"))) - {"extra"}
        assert sections <= set(adapter_cls.PROFILE_SECTIONS), (asset["name"], sections)


def test_every_connector_declares_only_known_profile_sections():
    caps = registry.profile_capabilities
    assert {"wazuh", "crowdstrike", "qualys", "aws", "entra_id", "okta"} <= set(caps)
    for cid, c in caps.items():
        assert set(c["sections"]) <= set(SECTIONS), cid


# ── CrowdStrike ──────────────────────────────────────────────────────────────

CS = "https://api.crowdstrike.com"


@responses.activate
def test_crowdstrike_maps_hosts_detections_and_spotlight_onto_the_profile():
    responses.add(responses.POST, f"{CS}/oauth2/token", json={"access_token": "t", "expires_in": 1800}, status=201)
    responses.add(responses.GET, f"{CS}/devices/combined/devices/light/v1", json={"resources": [{
        "device_id": "aid1", "hostname": "FIN-LT-07", "platform_name": "Windows",
        "os_product_name": "Windows 11 Pro", "os_version": "Windows 11", "os_build": "22631",
        "agent_version": "7.10.18110", "last_seen": "2020-01-01T00:00:00Z", "first_seen": "2019-06-01T00:00:00Z",
        "local_ip": "10.1.2.3", "external_ip": "41.90.1.1", "mac_address": "AA-BB-CC-00-11-22",
        "serial_number": "5CG1234", "system_manufacturer": "HP", "system_product_name": "EliteBook 840",
        "product_type_desc": "Workstation", "reduced_functionality_mode": "yes",
        "device_policies": {"prevention": {"applied": True}}, "last_login_user": "jdoe",
    }]})
    responses.add(responses.GET, f"{CS}/detects/queries/detects/v1", json={"resources": ["ldt:1"]})
    responses.add(responses.POST, f"{CS}/detects/entities/summaries/GET/v1", json={"resources": [{
        "detection_id": "ldt:1", "max_severity_displayname": "High",
        "device": {"device_id": "aid1", "hostname": "FIN-LT-07"},
        "behaviors": [{"display_name": "CredentialDumping"}],
    }]})
    responses.add(
        responses.GET, f"{CS}/spotlight/combined/vulnerabilities/v1",
        match=[matchers.query_param_matcher(
            {"filter": "status:'open'", "limit": "500", "facet": ["cve", "host_info"]})],
        json={"resources": [
            {"aid": "aid1", "host_info": {"hostname": "FIN-LT-07"},
             "apps": [{"product_name_version": "Google Chrome 120.0"}],
             "cve": {"id": "CVE-2024-0519", "severity": "HIGH", "base_score": 8.8}},
            {"aid": "aid1", "host_info": {"hostname": "FIN-LT-07"},
             "apps": [{"product_name_version": "Google Chrome 120.0"}],
             "cve": {"id": "CVE-2024-0001", "severity": "MEDIUM", "base_score": 5.0}},
        ]},
    )

    adapter = CrowdStrikeAdapter(tenant_id="t", config={"client_id": "x", "client_secret": "y"})
    results, errors = adapter.run_all_checks()
    assert errors == []
    by_check = {r.check_id: r for r in results}

    host = by_check["crowdstrike_stale_sensors"].discovered_assets[0]
    p = host["profile"]
    assert host["name"] == "FIN-LT-07" and host["vendor"] == "Microsoft"
    assert p["identity"]["serial_number"] == "5CG1234"
    assert p["identity"]["model"] == "EliteBook 840"
    assert p["health"]["status"] == "offline"                  # last seen in 2020
    assert p["os"]["name"] == "Windows 11 Pro"
    assert p["network"] == {"ip_addresses": ["10.1.2.3"], "public_ip": "41.90.1.1",
                            "mac_addresses": ["aa:bb:cc:00:11:22"]}
    assert p["protection"]["status"] == "Reduced functionality mode"
    assert p["protection"]["policy"] == "Prevention policy applied"
    assert p["ownership"]["assigned_user"] == "jdoe"

    activity = by_check["crowdstrike_high_severity_detections"].discovered_assets[0]
    assert activity["profile_only"] is True
    assert activity["profile"]["activity"]["alerts_by_level"] == {"High": 1}
    assert activity["profile"]["activity"]["recent_alerts"] == ["High: CredentialDumping"]

    spot = by_check["crowdstrike_critical_vulnerabilities"].discovered_assets[0]
    assert spot["profile"]["vulnerabilities"]["counts_by_severity"] == {"High": 1, "Medium": 1}
    assert spot["profile"]["software"]["vulnerable_packages"][0]["name"] == "Google Chrome 120.0"
    # Only High/Critical become Vulnerability nodes, same cutoff as Wazuh.
    assert [v["cve_id"] for v in spot["vulnerabilities"]] == ["CVE-2024-0519"]
    assert spot["vulnerabilities"][0]["severity"] == "High"

    for r in results:
        _assert_within_capability(CrowdStrikeAdapter, r.discovered_assets)


# ── Qualys ───────────────────────────────────────────────────────────────────

QB = "https://qualysapi.qualys.com"
HOSTS_XML = """<?xml version="1.0"?><HOST_LIST_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1001</ID><IP>10.0.0.12</IP><DNS>web-01.internal</DNS><OS>Windows Server 2019</OS>
    <LAST_VULN_SCAN_DATETIME>2026-09-20T03:00:00Z</LAST_VULN_SCAN_DATETIME></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>"""
CONFIRMED_XML = """<?xml version="1.0"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1001</ID><DNS>web-01.internal</DNS><LAST_SCAN_DATETIME>2026-09-20T03:00:00Z</LAST_SCAN_DATETIME>
    <DETECTION_LIST>
      <DETECTION><QID>1</QID><SEVERITY>5</SEVERITY></DETECTION>
      <DETECTION><QID>2</QID><SEVERITY>4</SEVERITY></DETECTION>
      <DETECTION><QID>3</QID><SEVERITY>4</SEVERITY></DETECTION>
    </DETECTION_LIST></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""


@responses.activate
def test_qualys_maps_host_list_and_confirmed_detections_onto_the_profile():
    responses.add(responses.GET, f"{QB}/api/2.0/fo/asset/host/", body=HOSTS_XML, content_type="text/xml")
    responses.add(responses.GET, f"{QB}/api/2.0/fo/asset/host/vm/detection/", body=CONFIRMED_XML, content_type="text/xml")
    adapter = QualysAdapter(tenant_id="t", config={"username": "u", "password": "p"})

    hosts = adapter.run_check("qualys_stale_scans").discovered_assets
    assert hosts[0]["name"] == "web-01.internal"
    assert hosts[0]["vendor"] == "Microsoft"
    assert hosts[0]["profile"]["os"] == {"name": "Windows Server 2019"}
    assert hosts[0]["profile"]["network"]["ip_addresses"] == ["10.0.0.12"]
    assert hosts[0]["profile"]["identity"]["agent_id"] == "1001"

    vulns = adapter.run_check("qualys_confirmed_high_severity").discovered_assets
    assert vulns[0]["profile_only"] is True
    v = vulns[0]["profile"]["vulnerabilities"]
    assert v["counts_by_severity"] == {"Critical": 1, "High": 2}
    assert v["total"] == 3
    assert v["last_scanned"] == "2026-09-20T03:00:00Z"

    _assert_within_capability(QualysAdapter, hosts + vulns)


# ── AWS (moto) ───────────────────────────────────────────────────────────────

@mock_aws
def test_aws_discovers_ec2_instances_and_flags_internet_exposed_admin_ports():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    open_sg = ec2.create_security_group(GroupName="ssh-open", Description="open")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=open_sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    closed_sg = ec2.create_security_group(GroupName="https-only", Description="ok")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=closed_sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                      SecurityGroupIds=[open_sg],
                      TagSpecifications=[{"ResourceType": "instance",
                                          "Tags": [{"Key": "Name", "Value": "bastion"}]}])
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.small",
                      SecurityGroupIds=[closed_sg])

    adapter = AWSAdapter(tenant_id="t", config={
        "aws_access_key_id": "k", "aws_secret_access_key": "s", "region": "us-east-1"})
    result = adapter.run_check("aws_ec2_exposure")

    assert result.total_count == 2
    by_name = {a["name"]: a for a in result.discovered_assets}
    bastion = by_name["bastion"]["profile"]
    assert bastion["cloud"]["provider"] == "AWS"
    assert bastion["cloud"]["region"] == "us-east-1"
    assert bastion["cloud"]["instance_type"] == "t3.micro"
    assert bastion["cloud"]["security_groups"] == ["ssh-open"]
    assert bastion["identity"]["cloud_instance_id"].startswith("i-")
    assert bastion["health"]["status"] == "running"
    # Unnamed instance falls back to its instance id.
    assert any(name.startswith("i-") for name in by_name)
    assert bastion["network"]["public_ip"]                    # moto's default subnets assign one
    assert result.affected_count == 1                          # only the SSH-open one counts
    assert bastion["cloud"]["public_exposure"] == ["22/tcp (SSH) open to the internet"]
    _assert_within_capability(AWSAdapter, result.discovered_assets)


def test_aws_open_admin_port_detection():
    open_ports = AWSAdapter._open_admin_ports
    assert open_ports({"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}) == ["3389/tcp (RDP)"]
    assert open_ports({"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                          "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}) == []
    assert open_ports({"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}) == ["all traffic"]


# ── Entra ID ─────────────────────────────────────────────────────────────────

@responses.activate
def test_entra_maps_directory_devices_onto_the_profile():
    responses.add(responses.POST, "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
                  json={"access_token": "t", "expires_in": 3600})
    responses.add(responses.GET, "https://graph.microsoft.com/v1.0/devices", json={"value": [
        {"deviceId": "d-1", "displayName": "SIMO-LT", "operatingSystem": "Windows",
         "operatingSystemVersion": "10.0.26100", "isCompliant": False, "isManaged": True,
         "approximateLastSignInDateTime": "2026-10-04T08:00:00Z", "registrationDateTime": "2026-01-01T00:00:00Z",
         "trustType": "AzureAd", "manufacturer": "HP", "model": "Pavilion", "accountEnabled": True},
        {"deviceId": "d-2", "displayName": "iPhone", "operatingSystem": "iOS", "isCompliant": True,
         "trustType": "Workplace", "accountEnabled": True},
    ]})
    adapter = EntraIDAdapter(tenant_id="t", config={"azure_tenant_id": "tid", "client_id": "c", "client_secret": "s"})
    result = adapter.run_check("entra_device_compliance")

    assert result.total_count == 2 and result.affected_count == 1
    laptop = {a["name"]: a for a in result.discovered_assets}["SIMO-LT"]
    assert laptop["vendor"] == "Microsoft"
    assert laptop["profile"]["identity"]["device_type"] == "Entra joined"
    assert laptop["profile"]["ownership"] == {"managed": True, "compliant": False}
    assert laptop["profile"]["health"]["last_seen"] == "2026-10-04T08:00:00Z"
    _assert_within_capability(EntraIDAdapter, result.discovered_assets)


# ── Okta ─────────────────────────────────────────────────────────────────────

@responses.activate
def test_okta_maps_registered_devices_onto_the_profile():
    responses.add(responses.GET, "https://org.okta.com/api/v1/devices", json=[
        {"id": "guo1", "status": "ACTIVE", "created": "2026-03-01T00:00:00.000Z",
         "profile": {"displayName": "Simo's MacBook", "platform": "MACOS", "manufacturer": "Apple",
                     "model": "MacBookPro18,3", "osVersion": "14.6", "serialNumber": "C02XYZ",
                     "diskEncryptionType": "ALL_INTERNAL_VOLUMES", "secureHardwarePresent": True},
         "_embedded": {"users": [{"managementStatus": "NOT_MANAGED",
                                  "user": {"profile": {"login": "simo@example.com"}}}]}},
        {"id": "guo2", "status": "ACTIVE", "profile": {"displayName": "old-pc", "platform": "WINDOWS",
                                                       "diskEncryptionType": "NONE"}},
    ])
    adapter = OktaAdapter(tenant_id="t", config={"org_url": "https://org.okta.com", "api_token": "x"})
    result = adapter.run_check("okta_device_assurance")

    assert result.total_count == 2 and result.affected_count == 1
    mac = {a["name"]: a for a in result.discovered_assets}["Simo's MacBook"]
    assert mac["profile"]["identity"]["serial_number"] == "C02XYZ"
    assert mac["profile"]["ownership"] == {"assigned_user": "simo@example.com", "managed": False}
    # Okta-only detail stays visible under "Other details".
    assert normalize_profile(mac["profile"])["extra"] == {
        "device_security.disk_encryption": "ALL_INTERNAL_VOLUMES",
        "device_security.secure_hardware": True,
    }
    _assert_within_capability(OktaAdapter, result.discovered_assets)
