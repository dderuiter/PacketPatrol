   M S B A M L   `   `   `  ����  PacketPatrol    PacketPatrol.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	     � 
ResizeMode$  NoResize=�5   	    � Title$, &Packet Patrol - (Creator: D. DeRuiter)��5   	   $	��650��68   $
��1000��6E   .��5      � $��0,0,0,0q�6   ���	#FF2C7386.+�5   
   �� -   5         ��Name$ cb_Interfaces��5      $
��Left=�6*   $��
65,10,10,0q�6E   $	��150��6Y    � ToolTip$ Select an interface.��6e   $��20��6�   $	��Top=�6�   �� 5	   
   -   5         ��Name$ b_Start��5	      $��Start��6"   $��20��6L   $
��Left=�6X   $	��Top=�6s   $��
240,10,0,0q�6�   $��50��6�   &   System.Windows.Controls.DataGrid  5   
   -   5          Name$ packetDataGrid��5      $��
10,40,0,10q�6+      
IsReadOnly . $
��Left=�6   $	��625��6�   ���	#FF474747
�������   RowStyle 5      �� 5       �� 
TargetType)  #System.Windows.Controls.DataGridRow"  6   .�5      �� 	 �� Property	 � ��
 �� Value
 �	#FF47474763   �� 5      	 � ��

 �����63    �� Triggers 5      P� 5       P� Property �@J�IsMouseOver P� Value . . �5      �� 	 � ��

 �   �6;   �� 5      	 � ��
 �	#FFF1D1576;   5      P� 5       �@ 
IsSelected . . �5      �� 	 � ��

 �����6;   �� 5      	 � ��
 �	#FFF1D1576;   5      5         Columns 5      0  *System.Windows.Controls.DataGridTextColumn  5      -   5        dgtc_Number��,  &System.Windows.Controls.DataGridColumn   Header$	 No.��5   :      CanUserReorder .  1  +System.Windows.Controls.DataGridBoundColumn   Binding 6G   �� *number+6b     5      -   5        	dgtc_Time��$
 Time��5   8    .   6F   �� *	timeStamp+6d     5      -   5        dgtc_SourceIP��$ 	Source IP��5   <      Width5  /System.Windows.Controls.DataGridLengthConverter$
 Auto 6l    6O   �� *
sourceIP+6l     5       -   5        dgtc_DestinationIP��$ Destination IP��5    A   $
 Auto 6{    6Y   �� *destinationIP+6{     5!      -   5        dgtc_SourcePort��$ Source Port��5!   >    .   6S   �� *
sourcePort+6r     5"      -	   5        dgtc_DestinationPort��$ Destination Port��5"   C    .   6]   �� *destinationPort+6�     5#      -
   5        dgtc_Protocol��$ Protocol��5#   <    .   6N   �� *
protocol+6k     5$      -   5        dgtc_Length��$ Length��5$   :    .   6J   �� *length+6e   5&      �� 5(   
   $
��Left=�6   $��
765,44,0,0q�6/   $
��Wrap=�6C   $	��Top=�6W   $��Packet Detailed Info��6o   
�������6�   �� 5)   
   $��Right=�6   $��0,0,135,155q�60   $
��Wrap=�6E   $��Bottom=�6Y   $��Packet Bytes��6t   
�������6�   �� 5*   
   $
��Left=�6   $��	10,10,0,0q�6/   $
��Wrap=�6B   $	��Top=�6V   
��������� 6�   $�
Interface:��6�   �� 6�   �� 6�   6�   �� 5+   
   -   5         ��Name$ cb_ASCII��5+      $��ASCII��6%   $��Right=�65   $��
0,0,15,155q�6Q   $��Bottom=�6e   
�������6�   �� 5-   
   
���   �$��1q�6%   $��Right=�69   $	��360��6U   $��	0,70,10,0q�6b   $	��Top=�6u   $	��325��6�   ._�5.      �� $
��Auto=�6   .��5/      R� -   5         R�Name$ tv_PacketInfo��5/      
����������	#FFC6C6C6��. ��50      �� 51      " Q�6    .�52      �� 	 �@Q�
IsExpanded
 . 6;   53      55      56      57      �� 58   
   
���   �$��1q�6%   $��Right=�69   $	��135��6U   $��	0,0,10,10q�6b   $��Bottom=�6u   $	��325��6�   ._�59      �� $
��Auto=�6   .��5:      �� -   5         ��Name$ tb_Bytes��5:      $
��Wrap=�6.    �� Padding$ 5q�6B   $�� ��6N   ���	#FFC6C6C6
���   ���. 6�   5;      5<      5>      5?      