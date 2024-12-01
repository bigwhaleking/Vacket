package controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;

import java.io.IOException;
import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.packet.format.FormatUtils;

public class Detail_Controller {

    @FXML
    private ListView<String> packetListView;
    private ObservableList<String> packetList = FXCollections.observableArrayList();
    

    // 선택된 장치의 인덱스를 설정하는 메서드
    public void setDeviceIndex(PcapIf device, PcapPacket packet, Ip4 ip, Tcp tcp, Udp udp, Payload payload) {
    	packetListView.setItems(packetList);
        startPacketView(device, packet, ip, tcp, udp, payload);
    }
    
    private void startPacketView(PcapIf device, PcapPacket packet, Ip4 ip, Tcp tcp, Udp udp, Payload payload) {
    	Task<Void> captureTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                if (device != null) {
				    viewDetailInfo(device, packet, ip, tcp, udp, payload);
				} 
				else {
				    Platform.runLater(() -> packetList.add("장치를 찾을 수 없습니다."));
				}
                return null;
            }
        };
        // 새로운 스레드에서 패킷 캡처 작업 실행
        Thread captureThread = new Thread(captureTask);
        captureThread.setDaemon(true);
        captureThread.start();
    }

    // 패킷 캡처를 시작하고 UI를 실시간으로 업데이트하는 메서드
    private void viewDetailInfo(PcapIf device, PcapPacket packet, Ip4 ip, Tcp tcp, Udp udp, Payload payload) throws IOException {  
    	
    	StringBuilder errbuf = new StringBuilder();
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_NON_BLOCKING;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            Platform.runLater(() -> packetList.add("패킷 캡처 실패: " + errbuf.toString()));
            return;
        }
        
        Ethernet eth = new Ethernet();

        int id = JRegistry.mapDLTToId(pcap.datalink());

        PcapPacket select_packet = packet;
        select_packet.scan(id);

        Platform.runLater(() -> {
            StringBuilder packetInfo = new StringBuilder();
            packetInfo.append("캡처 시간: ").append(new Date(select_packet.getCaptureHeader().timestampInMillis()))
                      .append("\n");

            if (select_packet.hasHeader(eth)) {
                packetInfo.append("출발지 MAC: ").append(FormatUtils.mac(eth.source())).append("\n")
                          .append("도착지 MAC: ").append(FormatUtils.mac(eth.destination())).append("\n");
            }

            if (select_packet.hasHeader(ip)) {
                packetInfo.append("출발지 IP: ").append(FormatUtils.ip(ip.source())).append("\n")
                          .append("도착지 IP: ").append(FormatUtils.ip(ip.destination())).append("\n");
                
                int protocol = ip.getUByte(9);
	    		
	    		//protocol == 6 은 TCP
	    		if(protocol == 6) {
	    			packetInfo.append(" protocol : TCP\n");
	    		}
	    		//protocol == 17 은 UDP
	    		if(protocol == 17) {
	    			packetInfo.append(" protocol : UDP\n");	
	    		}
	    		//protocol == 1 은 ICMP
	    		if(protocol == 1) {
	    			packetInfo.append(" protocol : ICMP\n");
	    		}
	    		//etc
	    		else {
	    			packetInfo.append(" protocol : ").append(protocol).append("\n");
	    		}
            }
            
          //4계층 정보에서 TCP 정보 추출 및 파일에 저장
	    	if(packet.hasHeader(tcp)) {
	    		packetInfo.append("출발지 TCP 정보 = ").append(tcp.source()).append("\n도착지 TCP 정보 = ").append(tcp.destination()).append("\n");
	    	}
	    	
	    	//4계층 정보에서 UDP 정보 추출 및 파일에 저장
	    	if(packet.hasHeader(udp)) {
	    		packetInfo.append("출발지 UDP 정보 = ").append(udp.source()).append("\n도착지 UDP 정보 = ").append(udp.destination()).append("\n");
	    	}
	    	
	    	//페이로드 추출 및 파일에 저장   
	     	if(packet.hasHeader(payload)) {
	     		packetInfo.append("페이로드의 길이 = ").append(payload.getLength()).append("\n");
	     		packetInfo.append(payload.toHexdump());
	    	}

            packetList.add(packetInfo.toString()); // 여러 줄로 구성된 패킷 정보 추가
        });
        
        pcap.close();
    	
    }
}