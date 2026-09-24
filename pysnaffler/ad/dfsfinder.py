"""
Port of SnaffCore/ActiveDirectory/DfsFinder.cs.

Finds DFS namespaces from AD so shares can be scanned through their namespace
path rather than once per replica. Covers both DFS v1 (the binary "pkt" blob on
fTDfs objects) and v2 (the XML target list on msDFS-Linkv2 objects).
"""
import struct
import xml.etree.ElementTree as ET

from ..concurrency import BlockingMq


class DFSShare:
    __slots__ = ("RemoteShareName", "RemoteServerName", "DFSFolderPath")

    def __init__(self, remote_share_name=None, remote_server_name=None,
                 dfs_folder_path=None):
        self.RemoteShareName = remote_share_name
        self.RemoteServerName = remote_server_name
        self.DFSFolderPath = dfs_folder_path

    def __repr__(self):
        return "<DFSShare \\\\%s\\%s -> %s>" % (
            self.RemoteServerName, self.RemoteShareName, self.DFSFolderPath)


class _Reader:
    """Little-endian cursor over the DFS blob."""

    def __init__(self, data, offset=0):
        self.data = data
        self.pos = offset

    def uint16(self):
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def uint32(self):
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def take(self, count):
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def unicode(self, byte_count):
        return self.take(byte_count).decode("utf-16-le", errors="replace")


class DfsFinder:
    def __init__(self):
        self.Mq = BlockingMq.get_mq()

    def find_dfs_shares(self, directory_search):
        return self.get_domain_dfs_share(directory_search)

    def get_domain_dfs_share(self, ds):
        shares = []
        shares.extend(self.get_domain_dfs_share_v1(ds))
        shares.extend(self.get_domain_dfs_share_v2(ds))
        return shares

    # -- DFS v1 --------------------------------------------------------------
    def get_domain_dfs_share_v1(self, directory_search):
        dfs_shares = []
        properties = ["remoteservername", "pkt", "cn", "name"]
        ldap_filter = "(&(objectClass=fTDfs))"

        try:
            entries = directory_search.query_ldap(ldap_filter, properties)
            for entry in entries:
                dfs_namespace = entry.DistinguishedName.replace("CN=", "").split(",")[0]

                remote_names = entry.get_property_as_array("remoteservername")
                pkt = entry.get_property_as_array_of_bytes("pkt")

                if remote_names:
                    for name in remote_names:
                        try:
                            if "\\" in name:
                                dfs_shares.append(DFSShare(
                                    remote_share_name=entry.get_property("name"),
                                    remote_server_name=name.split("\\")[2],
                                    dfs_folder_path=dfs_namespace))
                        except Exception as exc:
                            print("Error parsing DFSv1 share : " + str(exc))

                if pkt and pkt[0]:
                    for share in self.parse_pkt(pkt[0]) or []:
                        dfs_shares.append(share)
        except Exception as exc:
            print("Get-DomainDFSShareV1 error : " + str(exc))

        return dfs_shares

    # -- DFS v2 --------------------------------------------------------------
    def get_domain_dfs_share_v2(self, directory_search):
        dfs_shares = []
        properties = ["msdfs-linkpathv2", "msDFS-TargetListv2", "cn", "name"]
        ldap_filter = "(&(objectClass=msDFS-Linkv2))"

        try:
            entries = directory_search.query_ldap(ldap_filter, properties)
            for entry in entries:
                parts = entry.DistinguishedName.replace("CN=", "").split(",")
                if len(parts) < 2:
                    continue
                dfs_namespace = parts[1]

                target_list = entry.get_property_as_bytes("msdfs-targetlistv2")
                if not target_list:
                    continue
                try:
                    # strip the 2-byte length prefix, then it's UTF-16 XML
                    xml_text = target_list[2:].decode("utf-16-le", errors="replace")
                    root = ET.fromstring(xml_text)
                except Exception as exc:
                    print("Error in parsing DFSv2 share : " + str(exc))
                    continue

                for node in root.iter():
                    target = (node.text or "").strip()
                    if "\\" not in target:
                        continue
                    try:
                        target_parts = target.split("\\")
                        target_share_name = target_parts[3]
                        dfs_leaf_name = (entry.get_property("msdfs-linkpathv2") or "")
                        dfs_leaf_name = dfs_leaf_name.replace("/", "\\")
                        dfs_shares.append(DFSShare(
                            remote_share_name=target_share_name,
                            remote_server_name=target_parts[2],
                            dfs_folder_path="%s%s" % (dfs_namespace, dfs_leaf_name)))
                    except Exception as exc:
                        print("Error in parsing DFSv2 share : " + str(exc))
        except Exception as exc:
            print("Get-DomainDfsShareV2 error : " + str(exc))

        return dfs_shares

    # -- the v1 binary blob --------------------------------------------------
    @staticmethod
    def parse_pkt(pkt):
        """Port of Parse_Pkt - see MS-DFSNM / msdn cc227147."""
        shares = []
        object_list = []
        try:
            reader = _Reader(pkt)
            reader.uint32()                      # blob_version
            blob_element_count = reader.uint32()

            for _ in range(blob_element_count):
                blob_name_size = reader.uint16()
                blob_name = reader.unicode(blob_name_size)
                blob_data_size = reader.uint32()
                blob_data = reader.take(blob_data_size)

                prefix = None
                target_list = None

                if blob_name == "\\siteroot":
                    pass
                elif blob_name.startswith("\\domainroot"):
                    blob = _Reader(blob_data)
                    blob.take(16)                # root_or_link_guid
                    prefix = blob.unicode(blob.uint16())
                    blob.unicode(blob.uint16())  # short_prefix
                    blob.uint32()                # type
                    blob.uint32()                # state
                    comment_size = blob.uint16()
                    if comment_size:
                        blob.unicode(comment_size)
                    blob.take(8)                 # prefix_timestamp
                    blob.take(8)                 # state_timestamp
                    blob.take(8)                 # comment_timestamp
                    blob.uint32()                # version

                    dfs_targetlist_blob_size = blob.uint32()
                    dfs_targetlist_blob = blob.take(dfs_targetlist_blob_size)
                    reserved_blob_size = blob.uint32()
                    blob.take(reserved_blob_size)
                    blob.uint32()                # referral_ttl

                    targets = _Reader(dfs_targetlist_blob)
                    target_count = targets.uint32()
                    for _j in range(target_count):
                        targets.uint32()          # target_entry_size
                        targets.take(8)           # target_time_stamp
                        targets.uint32()          # target_state
                        targets.uint32()          # target_type
                        server_name = targets.unicode(targets.uint16())
                        share_name = targets.unicode(targets.uint16())
                        if target_list is None:
                            target_list = []
                        target_list.append("\\\\%s\\%s" % (server_name, share_name))

                object_list.append({"Name": blob_name, "Prefix": prefix,
                                    "TargetList": target_list})
        except (struct.error, IndexError, ValueError):
            # truncated or unexpected blob - keep whatever we already decoded
            pass

        for item in object_list:
            prefix = item["Prefix"]
            if prefix is None:
                continue
            parts = prefix.split("\\", 2)
            if len(parts) < 3:
                continue
            dfsns = parts[2]

            for target in (item["TargetList"] or []):
                target_parts = target.split("\\")
                if len(target_parts) < 4:
                    continue
                shares.append(DFSShare(
                    remote_share_name=target_parts[3],
                    remote_server_name=target_parts[2],
                    dfs_folder_path=dfsns))

        return shares
