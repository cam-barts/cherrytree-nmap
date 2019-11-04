# -*- coding: utf-8 -*-
from xml.dom import minidom
from xml.etree.ElementTree import tostring, Element, SubElement, ElementTree
from xml.etree import ElementTree
import argparse


def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, "utf-8")
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


def create_node(name, icon=None):
    if icon:
        return Element(
            "node", {"name": name, "custom_icon_id": icon, "prog_lang": "custom-colors"}
        )
    else:
        return Element("node", {"name": name, "prog_lang": "custom-colors"})


def create_richtext(text):
    node = Element("rich_text")
    node.text = text
    return node


def create_exploitation_node():
    exploit_node = create_node("Exploitation", "22")
    rt = """
Service Exploited:
        Vulnerability Type:
        Exploit POC:
    
    Description:


    Discovery of Vulnerability


    Exploit Code Used


    Proof\Local.txt File

        ☐ Screenshot with ifconfig\ipconfig
        ☐ Submit too OSCP Exam Panel
    """
    exploit_rich_text = create_richtext(rt)
    exploit_node.append(exploit_rich_text)
    return exploit_node


def create_post_exploitation_node():
    post_ex_node = create_node("Post Exploitation", "21")
    script_results = create_node("Script Results", "44")
    post_ex_node.append(script_results)
    host_info_node = create_node("Host Information", "18")
    host_info_rt = create_richtext(
        """
Operating System

Architecture

Domain

Installed Updates

Writeable Files\Directories

Installed Applications

Processes

Users

Groups

ipconfig/ifconfig

Network Processes

ARP

DNS

Route

Scheduled Tasks

Hashes

Passwords

Proof/Flags/Other
    """
    )
    host_info_node.append(host_info_rt)
    post_ex_node.append(host_info_node)
    return post_ex_node


def create_priv_esc_node():
    priv_esc_node = create_node("Privilege Escalation", "10")
    priv_esc_rt = create_richtext("""
Service Exploited:
            Vulnerability Type:
            Exploit POC:
        
        Description:

        Discovery of Vulnerability


        Exploit Code Used


        Proof\Local.txt File

            ☐ Screenshot with ifconfig\ipconfig
            ☐ Submit too OSCP Exam Panel
    """
    )
    priv_esc_node.append(priv_esc_rt)
    return priv_esc_node


class HostXML:
    def __init__(self, xml):
        self.xml = xml
        addresses = xml.getElementsByTagName("address")
        self.ip = [
            i.attributes["addr"].value
            if i.attributes["addrtype"].value == "ipv4"
            else None
            for i in addresses
        ][0]
        self.mac = [
            i.attributes["addr"].value
            if i.attributes["addrtype"].value == "mac"
            else None
            for i in addresses
        ][0]
        self.ports = [PortXML(port) for port in xml.getElementsByTagName("port")]

        hostnames = xml.getElementsByTagName("hostname")
        if len(hostnames):
            self.hostname = hostnames[0].attributes["name"].value
        else:
            self.hostname = None
        osmatches = xml.getElementsByTagName("osmatch")
        if len(osmatches):
            self.os = []
            for match in osmatches:
                self.os.append(
                    (match.attributes["name"].value, match.attributes["accuracy"].value)
                )
        else:
            self.os = None

        self.element = self.create_node()

    def get_host_information(self):
        print("=" * 25)
        print(f"IP Address: {self.ip}")
        if self.hostname:
            print(f"Host Name: {self.hostname}")
        print(f"MAC Address: {self.mac}")
        if self.os:
            print("Possible OS:")
            for i in self.os:
                print(f"\t{i[0]} ({i[1]}%)")
        print("-" * 25)
        print("Port Information")
        print("-" * 25)
        self.get_port_information()

    def get_port_information(self):
        for port in self.ports:
            port.get_service_info()
            port.get_script_info()

    def create_node(self):
        if self.hostname:
            name = f"{self.ip} ({self.hostname})"
        else:
            name = f"{self.ip}"
        icon = "10"

        host_node = create_node(name, icon)
        host_rt = f"""
IP Address: {self.ip}
Host Name: {self.hostname}
Mac Address: {self.mac}
Possible OS:
        """
        if self.os:
            for os in self.os:
                host_rt += f"\t{os[0]} ({os[1]}%)\n"
        host_rich_text = create_richtext(host_rt)
        host_node.append(host_rich_text)
        host_node.append(self.create_enumeration_node())
        host_node.append(create_exploitation_node())
        host_node.append(create_post_exploitation_node())
        host_node.append(create_priv_esc_node())
        return host_node

    def create_enumeration_node(self):
        enum_node = create_node("Enumeration", "21")
        tcp_node = create_node("TCP Ports", "18")
        udp_node = create_node("UDP Ports", "18")
        for port in self.ports:
            if port.is_TCP():
                tcp_node.append(port.element)
            else:
                udp_node.append(port.element)
        print(prettify(tcp_node))
        enum_node.append(tcp_node)
        enum_node.append(udp_node)
        return enum_node


class PortXML:
    def __init__(self, xml):
        self.xml = xml
        self.number = xml.attributes["portid"].value
        self.protocol = xml.attributes["protocol"].value
        self.service = xml.getElementsByTagName("service")[0]
        self.service_string = self.get_service_string()
        self.state = xml.getElementsByTagName("state")[0].attributes["state"].value
        self.scripts = xml.getElementsByTagName("script")
        self.element = self.create_node()

    def is_TCP(self):
        return self.protocol == "tcp"

    def is_open(self):
        if self.state == "open":
            return True
        else:
            return False

    def get_service_info(self):
        if self.is_open():
            print(f"Port Number: {self.number}")
            labels = ["Service", "Product", "Version", "Extra Information", "OS Type"]
            attrs = ["name", "product", "version", "extrainfo", "ostype"]
            for i in attrs:
                if self.service.hasAttribute(i):
                    print(
                        f"{labels[attrs.index(i)]}: {self.service.attributes[i].value}"
                    )

    def get_service_string(self):
        service_string = ""
        attrs = ["name", "product", "version", "extrainfo", "ostype"]
        for i in attrs:
            if self.service.hasAttribute(i):
                service_string += f"{self.service.attributes[i].value}"
        return service_string

    def get_script_info(self):
        for script in self.scripts:
            print(
                f"{script.attributes['id'].value} : {script.attributes['output'].value}"
            )

    def create_node(self):
        if self.state == "filtered":
            self.state = "open|filtered"
       	states = ["open", "open|filtered", "closed"]
        icon = str(states.index(self.state) + 1)
        name = f"{str(self.number)}: {self.service_string}"
        text = f"{str(self.number)}: {self.service_string}"
        for script in self.scripts:
            text += f"{script.attributes['id'].value} : {script.attributes['output'].value} \n"
        elm = create_node(name, icon)
        text_node = create_richtext(text)
        elm.append(text_node)
        return elm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", nargs="?", help="Nmap Xml to create cherrytree with")
    parser.add_argument(
        "outfile", nargs="?", default="nmap.ctd", help="Cherrytreefile to write"
    )
    args = parser.parse_args()

    if ".ctd" in args.outfile:
        outfile = args.outfile
    else:
        outfile = args.outfile + ".ctd"

    with open(args.infile) as infile:
        doc = minidom.parse(infile)
        print(doc.getElementsByTagName("host"))
    hosts = doc.getElementsByTagName("host")
    hosts_list = [HostXML(host).element for host in hosts]
    root = Element("cherrytree")
    root.extend(hosts_list)

    out_xml = prettify(root)

    with open(outfile, "w") as out:
        out.write(out_xml)


if __name__ == "__main__":
    main()
