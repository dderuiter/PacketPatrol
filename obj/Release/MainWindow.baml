   M S B A M L   `   `   `  ����   PacketPatrol    PacketPatrol.MainWindow   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml       � 
ResizeMode$  NoResize=� � Title$, &Packet Patrol - (Creator: D. DeRuiter)��$	��650��$
��1000��.��� $��0,0,0,0q����	#FF2C7386.+��� -    ��Name$ cb_Interfaces��$
��Left=�$��
65,10,10,0q�$	��150�� � ToolTip$ Select an interface.��$��20��$	��Top=��� -    ��Name$ b_Start��$��Start��$��20��$
��Left=�$	��Top=�$��
240,10,0,0q�$��50��&   System.Windows.Controls.DataGrid  -     Name$ packetDataGrid��$��
10,40,0,10q�   
IsReadOnly . $
��Left=�$	��625�����	#FF474747
�������   RowStyle ��  �� 
TargetType)  #System.Windows.Controls.DataGridRow"  .��� 	 �� Property	 � ��
 �� Value
 �	#FF474747�� 	 � ��

 ����� �� Triggers P�  P� Property �@J�IsMouseOver P� Value . . ��� 	 � ��

 �   ��� 	 � ��
 �	#FFF1D157P�  �@ 
IsSelected . . ��� 	 � ��

 ������� 	 � ��
 �	#FFF1D157   Columns 0  *System.Windows.Controls.DataGridTextColumn  -   dgtc_Number��,  &System.Windows.Controls.DataGridColumn   Header$	 No.��   CanUserReorder .  1  +System.Windows.Controls.DataGridBoundColumn   Binding �� *number+  -   	dgtc_Time��$
 Time�� .   �� *	timeStamp+  -   dgtc_SourceIP��$ 	Source IP��   Width5  /System.Windows.Controls.DataGridLengthConverter$
 Auto  �� *
sourceIP+  -   dgtc_DestinationIP��$ Destination IP��$
 Auto  �� *destinationIP+  -   dgtc_SourcePort��$ Source Port�� .   �� *
sourcePort+  -	   dgtc_DestinationPort��$ Destination Port�� .   �� *destinationPort+  -
   dgtc_Protocol��$ Protocol�� .   �� *
protocol+  -   dgtc_Length��$ Length�� .   �� *length+�� $
��Left=�$��
765,44,0,0q�$
��Wrap=�$	��Top=�$��Packet Detailed Info��
��������� $��Right=�$��0,0,135,155q�$
��Wrap=�$��Bottom=�$��Packet Bytes��
��������� $
��Left=�$��	10,10,0,0q�$
��Wrap=�$	��Top=�
��������� $�
Interface:���� �� �� -    ��Name$ cb_ASCII��$��ASCII��$��Right=�$��
0,0,15,155q�$��Bottom=�
��������� 
���   �$��1q�$��Right=�$	��360��$��	0,70,10,0q�$	��Top=�$	��325��._��� $
��Auto=�$��0q�.��R� -    R�Name$ tv_PacketInfo��
����������	#FFC6C6C6��. ���� " Q�.��� 	 �@Q�
IsExpanded
 . �� 
���   �$��1q�$��Right=�$	��135��$��	0,0,10,10q�$��Bottom=�$	��325��._��� $
��Auto=�.���� -    ��Name$ tb_Bytes��$
��Wrap=� �� Padding$ 5q�$�� �����	#FFC6C6C6
���   ���. 