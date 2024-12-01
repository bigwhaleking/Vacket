package controller;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;
import javafx.scene.*;

public class Controller implements Initializable {
	
	@FXML
	private ListView<String> networkListView;
	
	@FXML
	private TextArea textArea;
	
	@FXML
	private Button pickButton;

	ObservableList<String> networkList = FXCollections.observableArrayList();
	
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	public void initialize(URL location, ResourceBundle resources) {
		
		allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(allDevs, errbuf);
		
		if(r== Pcap.NOT_OK||allDevs.isEmpty()) {
			textArea.appendText("네트워크 장치가 없습니다.");
			return;
		}
		textArea.appendText("네트워크 장치를 찾았습니다.\n원하는 장치를 선택하세요.\n");
		
		for(PcapIf device : allDevs) {
			networkList.add(device.getName() + " " + ((device.getDescription() !=null)? device.getDescription() : "설명 없음"));
		}
		networkListView.setItems(networkList);
		
	}
	
	public void networkPickAction() {
		
		if(networkListView.getSelectionModel().getSelectedIndex()<0) {
			return;
		}
		
		int selectIndex = networkListView.getSelectionModel().getSelectedIndex();
		PcapIf select_device = allDevs.get(selectIndex);

		try {
			FXMLLoader loader = new FXMLLoader(getClass().getResource("../view/packetlist.fxml"));
			Parent root = loader.load();
			
			Packet_Controller packet_controller = loader.getController();
			packet_controller.setDeviceIndex(select_device);
			
			Stage stage = new Stage();
			stage.setTitle("Vacket");
			Scene scene = new Scene(root);
			stage.setScene(scene);
			stage.show();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
