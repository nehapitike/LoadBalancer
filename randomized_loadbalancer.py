Random Customized Controller:
"""
Customized Controller for performing Load balancing: CSE5300 ACN project
Load balancing technique: Random

"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time
import random
log = core.getLogger()

IDLE_TIMEOUT = 30 # in seconds
HARD_TIMEOUT = 0 # infinity

class iplb (EventMixin):
  class Server:
    def __init__ (self, ip, mac, port):
      self.ip = IPAddr(ip)
      self.mac = EthAddr(mac)
      self.port = port

    def __str__(self):
      return','.join([str(self.ip), str(self.mac), str(self.port)])
  
  def __init__ (self, connection):
    global IP
    global servers1

    self.connection = connection
    self.listenTo(connection)
    cnt=1
    a=[]
    for c in servers1:
        d=IPAddr(c)
        macc='00:00:00:00:00:0'+str(cnt)
        a.append(self.Server(d,macc, cnt))
        cnt=cnt+1

    self.serverslist =a
    self.server = 0
    self.lb_ip=IPAddr(IP)
    self.lb_mac=EthAddr('00:00:00:00:00:FE')

  def Random_load_servers (self):
    # Random: load the servers
    b = len(self.serverslist)
    num = random.randint(0, b-1)
    return self.serverslist[num]

  def handle_arp (self, packet, in_port):
    
    # Get the ARP request from packet
    arp_req = packet.next

    # Create ARP reply
    arp_rep = arp()
    arp_rep.opcode = arp.REPLY
    arp_rep.hwsrc = self.lb_mac #LOAD_BALANCER_MAC
    arp_rep.hwdst = arp_req.hwsrc
    arp_rep.protosrc =  self.lb_ip #LOAD_BALANCER_IP
    arp_rep.protodst = arp_req.protosrc

    # Create the Ethernet packet
    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.dst = packet.src
    eth.src = self.lb_mac # LOAD_BALANCER_MAC
    eth.set_payload(arp_rep)

    # Send the ARP reply to client
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.in_port = in_port
    self.connection.send(msg)

  def handle_arp1 (self, packet_in, out_port):
    
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def handle_request (self, packet, event):

    # Get the next server to handle the request
    server = self. Random_load_servers ()
    
    "First install the reverse rule from server to client"
    msg_sTc = of.ofp_flow_mod()
    msg_sTc.idle_timeout = IDLE_TIMEOUT
    msg_sTc.hard_timeout = HARD_TIMEOUT
    msg_sTc.buffer_id = None

    # Set packet matching
    # Match (in_port, src MAC, dst MAC, src IP, dst IP)
    msg_sTc.match.in_port = server.port
    msg_sTc.match.dl_src = server.mac
    msg_sTc.match.dl_dst = packet.src
    msg_sTc.match.dl_type = ethernet.IP_TYPE
    msg_sTc.match.nw_src = server.ip
    msg_sTc.match.nw_dst = packet.next.srcip

    msg_sTc.actions.append(of.ofp_action_nw_addr.set_src(self.lb_ip))
    msg_sTc.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
    msg_sTc.actions.append(of.ofp_action_output(port = event.port))
    self.connection.send(msg_sTc)
    
    "Second install the forward rule from client to server"
    msg_cTs = of.ofp_flow_mod()
    msg_cTs.idle_timeout = IDLE_TIMEOUT
    msg_cTs.hard_timeout = HARD_TIMEOUT
    msg_cTs.buffer_id = None
    msg_cTs.data = event.ofp # Forward the incoming packet

    # Set packet matching
    # Match (in_port, MAC src, MAC dst, IP src, IP dst)
    msg_cTs.match.in_port = event.port
    msg_cTs.match.dl_src = packet.src
    msg_cTs.match.dl_dst = self.lb_mac
    msg_cTs.match.dl_type = ethernet.IP_TYPE
    msg_cTs.match.nw_src = packet.next.srcip
    msg_cTs.match.nw_dst = self.lb_ip
    
    # Append actions
    # Set the dst IP and MAC to load balancer's
    # Forward the packet to server's port
    msg_cTs.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
    msg_cTs.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
    msg_cTs.actions.append(of.ofp_action_output(port = server.port))

    self.connection.send(msg_cTs)

    log.info("Installing %s <-> %s" % (packet.next.srcip, server.ip))

  def _handle_PacketIn (self, event):
    packet = event.parse()
    packet_in = event.ofp
    if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    elif packet.type == packet.ARP_TYPE:
    
      # Handle ARP request for load balancer
       if packet.next.protodst !=  self.lb_ip:
         log.debug("Receive an ARP request not for LB")
         self.handle_arp1(packet_in, of.OFPP_ALL)
         return

      log.debug("Receive an ARP request")
      self.handle_arp(packet, event.port)

    elif packet.type == packet.IP_TYPE:
      # Handle client's request

      # Only accept client request for load balancer
      if packet.next.dstip !=  self.lb_ip: 
        return

      log.debug("Receive an IPv4 packet from %s" % packet.next.srcip)
      self.handle_request(packet, event)
    
class SimpleLoadBalancer(EventMixin):
  def __init__ (self):
   
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % event.connection)
    iplb(event.connection)


def launch (ip,servers):
  global IP
  global servers1
  servers1 = servers.replace(","," ").split()
  servers1 = [IPAddr(x) for x in servers1]
  IP=IPAddr(ip)
  # Start load balancer
  core.registerNew(SimpleLoadBalancer)


