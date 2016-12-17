using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace PacketPatrol
{
    // Stores the protocol
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Socket mainSocket;                          //The socket which captures all incoming packets
        private byte[] byteData = new byte[4096];
        private bool bContinueCapturing = false;            //A flag to check if packets are to be captured or not
        public const int maxBufferSize = 1000;
        private static ArrayList packetBuffer = new ArrayList(100);
        private static Packet selectedPacket;
        private Thread captureThread;

        // Constructor
        public MainWindow()
        {
            InitializeComponent();

            Loaded += MainWindow_Loaded;
            Closed += MainWindow_Closed;
        }

        // Handles the event of loading the Main Window
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            string strIP = null;
            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));

            if (HosyEntry.AddressList.Length > 0)
            {
                // Loop through all interface addresses and populate interface Combo Box
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    cb_Interfaces.Items.Add(strIP);
                }
            }
        }

        // Handles the event of closing the Main Window
        private void MainWindow_Closed(object sender, EventArgs e)
        {
            // Check if still capturing packets
            if (bContinueCapturing)
            {
                //To stop capturing the packets close the socket
                mainSocket.Shutdown(SocketShutdown.Both);
                mainSocket.Close();
            }

            // Check if background thread still running
            if (captureThread != null && captureThread.IsAlive)
                captureThread.Abort();

            Application.Current.Shutdown();
        }

        // Handles the event of clicking the start Button
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            //packetDataGrid.Items.Add(new PacketData("1", "10:00", "Source", "Dest", "Pro", "len", "info"));

            if (cb_Interfaces.Text == "")
            {
                MessageBox.Show("Select an Interface to capture the packets.", "Packet Patrol", 
                    MessageBoxButton.OK);
                return;
            }
            try
            {
                //Check if we should start capturing the packets...
                if (!bContinueCapturing)
                {
                    //For sniffing the socket to capture the packets has to be a raw socket, with the
                    //address family being of type internetwork, and protocol being IP
                    mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                    //Bind the socket to the selected IP address
                    mainSocket.Bind(new IPEndPoint(IPAddress.Parse(cb_Interfaces.Text), 0));

                    //Set the socket  options
                    mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                               SocketOptionName.HeaderIncluded, //Set the include the header
                                               true);                           //option to true

                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    //Equivalent to SIO_RCVALL constant of Winsock 2
                    mainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);

                    b_Start.Content = "Stop";
                    bContinueCapturing = true;

                    //Capture using a thread
                    captureThread = new Thread(PacketReceived);
                    captureThread.Name = "Capture Thread";
                    captureThread.Start();
                }
                else
                {
                    b_Start.Content = "Start";
                    bContinueCapturing = false;

                    if (captureThread.IsAlive)
                        captureThread.Abort();

                    //To stop capturing the packets close the socket
                    mainSocket.Shutdown(SocketShutdown.Both);
                    mainSocket.Close();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Packet Patrol", MessageBoxButton.OK);
            }
        }

        // Handles the event of receiving new packets
        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                // Store the number of bytes received
                int nReceived = mainSocket.EndReceive(ar);

                //Analyze the bytes received
                ParseData(byteData, nReceived);

                if (bContinueCapturing)
                {
                    byteData = new byte[4096];

                    //Another call to BeginReceive so that we continue to receive the incoming
                    //packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        // Handles what happens when a packet is received
        private void PacketReceived()
        {

            while (bContinueCapturing)
            {
                try
                {
                    int bytesReceived = mainSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);

                    //Analyze the bytes received...
                    if (bytesReceived > 0)
                    {
                        ParseData(byteData, bytesReceived);
                    }

                    Array.Clear(byteData, 0, byteData.Length);
                }
                catch (ObjectDisposedException ex)
                {
                    Console.WriteLine(ex.Message);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }

        // Parses new packet data
        private void ParseData(byte[] byteData, int nReceived)
        {
            //Since all protocol packets are encapsulated in the IP datagram
            //so we start by parsing the IP header and see what protocol data
            //is being carried by it
            IPHeader ipHeader = new IPHeader(byteData, nReceived);

            //Now according to the protocol being carried by the IP datagram we parse 
            //the data field of the datagram
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);

                    if(!Dispatcher.CheckAccess())
                    {
                        Dispatcher.Invoke(() => 
                        {
                            Packet packet = CreatePacket(ipHeader, tcpHeader);

                            packet.bytesHEX = BitConverter.ToString(byteData).Replace("-","").Substring(0, nReceived * 2);
                            packet.bytesASCII = Encoding.ASCII.GetString(byteData).Replace("-","").Substring(0, nReceived);

                            TreeViewItem node = createPacketInfoNode(ipHeader, tcpHeader);
                            packet.node = node;

                            // Check if maximum buffer size reached
                            if (packetBuffer.Count == maxBufferSize)
                            {
                                // Update packet buffer
                                packetBuffer.RemoveAt(0);
                                packetBuffer.Add(packet);

                                // Update packet Data Grid View
                                packetDataGrid.Items.RemoveAt(0);
                                packetDataGrid.Items.Add(packet);
                            }
                            else
                            {
                                // Update packet buffer
                                packetBuffer.Add(packet);

                                // Update packet Data Grid View
                                packetDataGrid.Items.Add(packet);
                            }    
                        }
                        , DispatcherPriority.Normal);
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }
        }

        // Creates the packet and store in the buffer
        private Packet CreatePacket(IPHeader ipHeader, TCPHeader tcpHeader)
        {
            Packet packet = new Packet();

            // -------------------------------------------------------------------
            // IP Data
            // -------------------------------------------------------------------
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    packet.protocol = "TCP";
                    break;
                case Protocol.UDP:
                    packet.protocol = "UPD";
                    break;
                case Protocol.Unknown:
                    packet.protocol = "Unknown";
                    break;
            }

            // IPHeader.MessageLength stores the length of the data field
            packet.length = "" + ipHeader.MessageLength;
            packet.sourceIP = ipHeader.SourceAddress.ToString();
            packet.destinationIP = ipHeader.DestinationAddress.ToString();

            // -------------------------------------------------------------------
            // TCP Data
            // -------------------------------------------------------------------
            packet.sourcePort = tcpHeader.SourcePort;
            packet.destinationPort = tcpHeader.DestinationPort;

            return packet;
        }

        // Creates the Tree View Item node for the packet and stores it in the packet
        private TreeViewItem createPacketInfoNode(IPHeader ipHeader, TCPHeader tcpHeader)
        {
            // -------------------------------------------------------------------
            // IP Node
            // -------------------------------------------------------------------
            TreeViewItem ipNode = new TreeViewItem();

            ipNode.Header = "Internet Protocol (IP)";

            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipNode.Items.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipNode.Items.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipNode.Items.Add("Protocol: " + "Unknown");
                    break;
            }

            ipNode.Items.Add("Ver: " + ipHeader.Version);
            ipNode.Items.Add("Header Length: " + ipHeader.HeaderLength);
            ipNode.Items.Add("Differentiated Services: " + ipHeader.DifferentiatedServices);
            ipNode.Items.Add("Total Length: " + ipHeader.TotalLength);
            ipNode.Items.Add("Identification: " + ipHeader.Identification);
            ipNode.Items.Add("Flags: " + ipHeader.Flags);
            ipNode.Items.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipNode.Items.Add("Time to live: " + ipHeader.TTL);
            ipNode.Items.Add("Checksum: " + ipHeader.Checksum);
            ipNode.Items.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipNode.Items.Add("Destination: " + ipHeader.DestinationAddress.ToString());

            // -------------------------------------------------------------------
            // TCP Node
            // -------------------------------------------------------------------
            TreeViewItem tcpNode = new TreeViewItem();

            tcpNode.Header = "Transmission Control Protocol (TCP)";
            tcpNode.Items.Add("Sequence Number: " + tcpHeader.SequenceNumber);

            if (tcpHeader.AcknowledgementNumber != "")
                tcpNode.Items.Add("Acknowledgement Number: " + tcpHeader.AcknowledgementNumber);

            tcpNode.Items.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpNode.Items.Add("Flags: " + tcpHeader.Flags);
            tcpNode.Items.Add("Window Size: " + tcpHeader.WindowSize);
            tcpNode.Items.Add("Checksum: " + tcpHeader.Checksum);

            if (tcpHeader.UrgentPointer != "")
                tcpNode.Items.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);

            tcpNode.Items.Add("Source Port: " + tcpHeader.SourcePort);
            tcpNode.Items.Add("Destination Port: " + tcpHeader.DestinationPort);

            // Add TCP sub-node to IP node
            ipNode.Items.Add(tcpNode);

            return ipNode;
        }

        // Handles the event of double clicking on a Data Grid View row
        private void packetDataGrid_DoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (packetBuffer.Count == 0) return;

            // Determine row index selected
            int index = packetDataGrid.Items.IndexOf(packetDataGrid.CurrentItem);

            // Check if non-row selected
            if (index < 0) return;

            // Update bytes Text Box (if Check Box checked then show ASCII othwerise show HEX)
            selectedPacket = (packetBuffer[index] as Packet);
            tb_Bytes.Text = (cb_ASCII.IsChecked.Value == true) ? selectedPacket.bytesASCII : selectedPacket.bytesHEX;

            // Update packet info Tree View
            tv_PacketInfo.Items.Clear();
            tv_PacketInfo.Items.Add((packetBuffer[index] as Packet).node);
        }

        // Handles the event of the ASCII Check Box value change
        private void cb_ASCII_Changed(object sender, RoutedEventArgs e)
        {
            if (selectedPacket == null) return;

            // Update bytes Text Box (if Check Box checked then show ASCII othwerise show HEX)
            tb_Bytes.Text = (cb_ASCII.IsChecked.Value == true) ? selectedPacket.bytesASCII : selectedPacket.bytesHEX;
        }
    }
}
