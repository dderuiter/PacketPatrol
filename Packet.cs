using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace PacketPatrol
{
    class Packet
    {
        private static int id = 0;

        public string number { get; set; }
        public string timeStamp { get; set; }
        public string sourceIP { get; set; }
        public string destinationIP { get; set; }
        public string sourcePort { get; set; }
        public string destinationPort { get; set; }
        public string protocol { get; set; }
        public string length { get; set; }
        public string bytesHEX { get; set; }
        public string bytesASCII { get; set; }
        public TreeViewItem node { get; set; }

        public Packet()
        {
            this.number = "" + (++id % MainWindow.maxBufferSize);
            this.timeStamp = DateTime.Now.ToString("h:mm:ss tt");
            this.sourceIP = "";
            this.destinationIP = "";
            this.sourcePort = "";
            this.destinationPort = "";
            this.protocol = "";
            this.length = "";
            this.node = new TreeViewItem();
        }
    }
}
