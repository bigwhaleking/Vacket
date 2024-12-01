package controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;

import java.io.IOException;
import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.packet.format.FormatUtils;

public class Packet_Controller {

    @FXML
    private ListView<String> packetListView;
    
    @FXML
    private Button pickButton1;
    
    private ObservableList<String> packetList = FXCollections.observableArrayList();
    private ObservableList<PcapPacket> packetObjects = FXCollections.observableArrayList();
    
    private PcapPacket select_Packet;
    private PcapIf select_device;
    
    Ip4 select_ip;
    Tcp select_tcp;
    Udp select_udp;
    Payload select_payload;

    // 선택된 장치의 인덱스를 설정하는 메서드
    public void setDeviceIndex(PcapIf device) {
    	select_device = device;
        packetListView.setItems(packetList); // ListView에 ObservableList 연결
        startPacketCapture(device); // 패킷 캡처 시작
    }

    // 패킷 캡처를 시작하고 UI를 실시간으로 업데이트하는 메서드
    private void startPacketCapture(PcapIf device) {
        Task<Void> captureTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                try {
                    if (device != null) {
                        capturePackets(device);
                    } else {
                        Platform.runLater(() -> packetList.add("장치를 찾을 수 없습니다."));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return null;
            }
        };

        // 새로운 스레드에서 패킷 캡처 작업 실행
        Thread captureThread = new Thread(captureTask);
        captureThread.setDaemon(true);
        captureThread.start();
    }

    // 패킷을 캡처하고, 캡처한 내용을 ListView에 업데이트
    private void capturePackets(PcapIf device) throws IOException {
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
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Payload payload = new Payload();
        
        select_ip = ip;
        select_tcp = tcp;
        select_udp = udp;
        select_payload = payload;
        
        PcapHeader header = new PcapHeader();
        JBuffer buf = new JBuffer(JMemory.POINTER);
        int id = JRegistry.mapDLTToId(pcap.datalink());
        
        while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
        	PcapPacket packet = new PcapPacket(header, buf);
            packet.scan(id);
            
            Platform.runLater(() -> {
                StringBuilder packetInfo = new StringBuilder();
                packetInfo.append("[ ").append(packet.getFrameNumber()).append(" ] ")
                          .append(new Date(packet.getCaptureHeader().timestampInMillis()))
                          .append(" - ");

                if (packet.hasHeader(ip)) {
                    packetInfo.append("출발지 IP: ").append(FormatUtils.ip(ip.source()))
                              .append(", 도착지 IP: ").append(FormatUtils.ip(ip.destination()))
                              .append(" | ");
                    
                    int protocol = ip.getUByte(9);
    	    		
    	    		//protocol == 6 은 TCP
    	    		if(protocol == 6) {
    	    			packetInfo.append(" protocol : TCP\n");
    	    		}
    	    		//protocol == 17 은 UDP
    	    		else if(protocol == 17) {
    	    			packetInfo.append(" protocol : UDP\n");
    	    		}
    	    		//protocol == 1 은 ICMP
    	    		else if(protocol == 1) {
    	    			packetInfo.append(" protocol : ICMP\n");
    	    		}
    	    		//etc
    	    		else {
    	    			packetInfo.append(" protocol : ").append(protocol);
    	    		}
                }
           
                packetList.add(packetInfo.toString());
                packetObjects.add(packet);
            });
        }

        pcap.close();
    }
    
    @FXML
    private void initialize() {
        // ListView에서 항목 선택 시 이벤트 핸들러 추가
        packetListView.setOnMouseClicked(this::handlePacketSelection);
    }

    // ListView 항목 클릭 시 선택된 패킷 설정
    private void handlePacketSelection(MouseEvent event) {
        int selectedIndex = packetListView.getSelectionModel().getSelectedIndex();
        if (selectedIndex >= 0) {
        	select_Packet = packetObjects.get(selectedIndex); // 사용자가 선택한 패킷 객체 저장
        }
    }

    public void packetPickAction() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("../view/detailpacketlist.fxml"));
            AnchorPane secondLayout = loader.load();
            
            Detail_Controller detail_controller = loader.getController();
            detail_controller.setDeviceIndex(select_device, select_Packet, select_ip, select_tcp, select_udp, select_payload);

            Stage secondStage = new Stage();
            secondStage.setTitle("Vacket");
            secondStage.setScene(new Scene(secondLayout));
            secondStage.show();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}