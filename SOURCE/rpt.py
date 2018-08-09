''' 
Packet Sensor/Recorder Report Template
Version Book Release
    
Copyright (c) 2018 Python Forensics and Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.
    
'''

# Special Alert Report Template

AHTML_START = '''
<html>
<head>
	<title>Python Forensics Alert Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>Alert Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Alert Observations</b></font></span></span></u></p>
<hr>
'''

AHTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1600px;">
	<tbody>
		<tr>
                        <td style="width: 250px;"><strong>Alert</strong></td>                 
                        <td style="width: 250px;">{fldAlert}</td>                       
                        <td style="width: 250px;"><strong>Alerts-Observed</strong></td> 
                        <td style="width: 250px;">{fldAlertCnt}</td>
		</tr>
                <tr>
                        <td style="width: 250px;"><strong>Last Observed</strong></td> 
                        <td style="width: 250px;">{fldTimeStamp}</td>
                </tr>
                <tr>     
                        <td style="width: 250px;"><strong>SrcIP</strong></td>
                        <td style="width: 250px;"><strong>DstIP</strong></td>
                        <td style="width: 250px;"><strong>Frame-Type</strong></td>
                        <td style="width: 250px;"><strong>Protocol</strong></td>
                </tr>
                <tr>
                        <td style="width: 250px;">{fldSrcIP}</td>
                        <td style="width: 250px;">{fldDstIP}</td>
                        <td style="width: 250px;">{fldFrameType}</td>
                        <td style="width: 250px;">{fldProtocol}</td>
                </tr>
                                
                <tr>
                        <td style="width: 250px;"><strong>SrcPort</strong></td>
                        <td style="width: 250px;"><strong>SrcPortName</strong></td>
                        <td style="width: 250px;"><strong>DstPort</strong></td>
                        <td style="width: 250px;"><strong>DstPortName</strong></td>
		</tr>
                <tr>
                        <td style="width: 150px;">{fldSrcPort}</td>
                        <td style="width: 250px;">{fldSrcPortName}</td>
                        <td style="width: 150px;">{fldDstPort}</td>
                        <td style="width: 250px;">{fldDstPortName}</td>
		</tr>
                
                <tr>
                        <td style="width: 250px;"><strong>SrcMAC</strong></td>
                        <td style="width: 250px;"><strong>DstMAC</strong></td>
                        <td style="width: 250px;"><strong>PckSize</strong></td>
		</tr>
                <tr>
                        <td style="width: 250px;">{fldSrcMAC}</td>
                        <td style="width: 250px;">{fldDstMAC}</td>
                        <td style="width: 250px;">{fldPckSize}</td>
		</tr>

                <tr>
                        <td style="width: 250px;"><strong>SrcCountry</strong></td>
                        <td style="width: 250px;"><strong>DstCountry</strong></td>
                        <td style="width: 250px;"><strong>SrcMFG</strong></td>
                        <td style="width: 250px;"><strong>DstMFG</strong></td>
		</tr>
                <tr>
                        <td style="width: 250px;">{fldSrcCC}</td>
                        <td style="width: 250px;">{fldDstCC}</td>
                        <td style="width: 250px;">{fldSrcMFG}</td>
                        <td style="width: 250px;">{fldDstMFG}</td>
		</tr>

	</tbody>
</table>

'''

# Special Report Template

CHTML_START = '''
<html>
<head>
	<title>Python Forensics Country Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>Country Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Unique Country Observations</b></font></span></span></u></p>

<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1000px;">
	<tbody>
		<tr>
                        <td style="width: 250px;"><strong>Country</strong></td>
                        <td style="width: 150px;"><strong>Count</strong></td>
		</tr>
	</tbody>
</table>

'''

CHTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1000px;">
	<tbody>
		<tr>
                        <td style="width: 250px;">{fldCountry}</td>
                        <td style="width: 150px;">{fldHits}</td>
		</tr>
	</tbody>
</table>

'''

IHTML_START = '''
<html>
<head>
	<title>Python Forensics Possible ICS Activity Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>ICS Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Possible ICS Observations</b></font></span></span></u></p>

<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:2100px;">
	<tbody>
		<tr>
                        <td style="width: 150px;"><strong>Port</strong></td>
                        <td style="width: 150px;"><strong>Count</strong></td>
                        <td style="width: 400px;"><strong>Port Name</strong></td>
			<td style="width: 150px;"><strong>MAC Address</strong></td>
                        <td style="width: 400px;"><strong>SRC MFG</strong></td>
                        <td style="width: 400px;"><strong>DST MFG</strong></td>
                        <td style="width: 150px;"><strong>IP Address</strong></td>
		</tr>
	</tbody>
</table>

'''

IHTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:2100px;">
	<tbody>
		<tr>
                        <td style="width: 150px;"><strong>{fldPort}</strong></td>
                        <td style="width: 150px;"><strong>{fldHits}</strong></td>
                        <td style="width: 400px;"><strong>{fldPortName}</strong></td>
			<td style="width: 150px;"><strong>{fldMAC}</strong></td>
                        <td style="width: 400px;"><strong>{fldSrcMFG}</strong></td>
                        <td style="width: 400px;"><strong>{fldDstMFG}</strong></td>
                        <td style="width: 150px;"><strong>{fldIP}</strong></td>
		</tr>
	</tbody>
</table>

'''

THTML_START = '''
<html>
<head>
	<title>Python Forensics Possible IoT Activity Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>IoT Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Possible IoT Observations</b></font></span></span></u></p>

'''

THTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:2400px;">
	<tbody>
                <tr>
                        <td style="width: 150px;"><strong>Observed</strong></td>
                        <td style="width: 150px;"><strong>Src IP</strong></td>
                        <td style="width: 150px;"><strong>Dst IP</strong></td>
                </tr>
		<tr>
                        <td style="width: 150px;">{fldHits}</td>
                        <td style="width: 150px;">{fldSrcIP}</td>
                        <td style="width: 150px;">{fldDstIP}</td>
                </tr>
                <tr>
                        <td style="width: 150px;"><strong>Src Port</strong></td>
                        <td style="width: 400px;"><strong>SrcPort Name</strong></td>
                        <td style="width: 400px;"><strong>Dst Port</strong></td>
                        <td style="width: 400px;"><strong>DstPort Name</strong></td>
                </tr>
                <tr>
                        <td style="width: 150px;">{fldSrcPort}</td>
                        <td style="width: 400px;">{fldSrcPortName}</td>
                        <td style="width: 400px;">{fldDstPort}</td>
                        <td style="width: 400px;">{fldDstPortName}</td>
                </tr>
                
                <tr>
			<td style="width: 150px;"><strong>Src MAC</strong></td>
                        <td style="width: 400px;"><strong>Src MFG</strong></td>
                        <td style="width: 150px;"><strong>Dst MAC</strong></td>
                        <td style="width: 400px;"><strong>Dst MFG</strong></td>
		</tr>
                <tr>
			<td style="width: 150px;">{fldSrcMAC}</td>
                        <td style="width: 400px;">{fldSrcMFG}</td>
                        <td style="width: 150px;">{fldDstMAC}</td>
                        <td style="width: 400px;"><{fldDstMFG}</td>
		</tr>
	</tbody>
</table>

'''

MHTML_START = '''
<html>
<head>
	<title>Python Forensics Device MFG Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>Manufacturer Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>MFG Observations</b></font></span></span></u></p>

<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1800px;">
	<tbody>
		<tr>
                        <td style="width: 400px;"><strong>Manufacturer</strong></td>
                        <td style="width: 400px;"><strong>MAC Address</strong></td>
                        <td style="width: 400px;"><strong>IP Address</strong></td>
		</tr>
	</tbody>
</table>

'''

MHTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1800px;">
	<tbody>
		<tr>
                        <td style="width: 400px;">{fldMFG}</td>
                        <td style="width: 400px;">{fldMAC}</td>
                        <td style="width: 400px;">{fldIP}</td>
		</tr>
	</tbody>
</table>

'''

PHTML_START = '''
<html>
<head>
	<title>Python Forensics Port Usage Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong>Port Usage Report {fldDate} <strong></span></span></span></p>

<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Port Usage Observations</b></font></span></span></u></p>

<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1800px;">
	<tbody>
		<tr>
                        <td style="width: 150px;"><strong>Port</strong></td>
                        <td style="width: 200px;"><strong>PortName</strong></td>
                        <td style="width: 400px;"><strong>Src IP</strong></td>
                        <td style="width: 400px;"><strong>Dst IP</strong></td>
                        <td style="width: 150px;"><strong>Frame</strong></td>
                        <td style="width: 150px;"><strong>Protocol</strong></td>
		</tr>
	</tbody>
</table>

'''

PHTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1800px;">
	<tbody>
		<tr>
                        <td style="width: 150px;">{fldPort}</td>
                        <td style="width: 200px;">{fldPortName}</td>
                        <td style="width: 400px;">{fldSrcIP}</td>
                        <td style="width: 400px;">{fldDstIP}</td>
                        <td style="width: 150px;">{fldFrame}</td>
                        <td style="width: 150px;">{fldProtocol}</td>
		</tr>
	</tbody>
</table>

'''

# Master Report Template

HTML_START = '''
<html>
<head>
	<title>Python Forensics Master Report</title>
</head>
<body style="cursor: auto;">
<p><span style="color:#B22222;"><span style="font-size:36px;"><span style="font-family:tahoma,geneva,sans-serif;"><strong> Master Report {fldDate}<strong></span></span></span></p>
<p><u><span style="color:#808080;"><span style="font-size:24px;"><font face="tahoma, geneva, sans-serif"><b>Observations</b></font></span></span></u></p>

<body style="cursor: auto;">

'''
HTML_BODY = '''
<body style="cursor: auto;">
<table border="2" cellpadding="1" cellspacing="1" style="width:1400;">
	<tbody>
                <tr>
                        <td style="width: 200px;"><strong>Alert</strong></td> 
                        <td style="width: 200px;">{fldAlert}</td>
                </tr>
                
		<tr>
                        <td style="width: 200px;"><strong>Src-IP</strong></td>
                        <td style="width: 200px;"><strong>Dst-IP</strong></td>
                        <td style="width: 100px;"><strong>Protocol</strong></td>
                        <td style="width: 150px;"><strong>Frame-Type</strong></td>      
                        
                </tr>
                <tr>
                        <td style="width: 200px;">{fldSrcIP}</td>
                        <td style="width: 200px;">{fldDstIP}</td>
                        <td style="width: 100px;">{fldProtocol}</td>
                        <td style="width: 150px;">{fldFrame}</td>  
                </tr>
                               
                <tr>
                        <td style="width: 200px;"><strong>Src-Port</strong></td>
                        <td style="width: 200px;"><strong>Src-Port Name</strong></td>
                        <td style="width: 200px;"><strong>Dst-Port</strong></td>
                        <td style="width: 200px;"><strong>Dst-Port name</strong></td>     

                </tr>
                <tr>
                        <td style="width: 200px;">{fldSrcPort}</td>
                        <td style="width: 200px;">{fldSrcPortName}</td>
                        <td style="width: 200px;">{fldDstPort}</td>
                        <td style="width: 200px;">{fldDstPortName}</td>  
                </tr>
                <tr>
                        <td style="width: 200px;"><strong>Src-MAC</strong></td>
                        <td style="width: 400px;"><strong>Src-MFG Name</strong></td>
                        <td style="width: 200px;"><strong>Dst-MAC</strong></td>
                        <td style="width: 400px;"><strong>Dst-MFG Name</strong></td>    
                </tr>
                <tr>
                        <td style="width: 200px;">{fldSrcMAC}</td>
                        <td style="width: 400px;">{fldSrcMFG}</td>
                        <td style="width: 200px;">{fldDstMAC}</td>
                        <td style="width: 400px;">{fldDstMFG}</td>
                </tr>
                
                <tr>
                        <td style="width: 300px;"><strong>Src Country</strong></td>
                        <td style="width: 300px;"><strong>Dst Country</strong></td>
		</tr>
                <tr>
                        <td style="width: 300px;">{fldSrcCC}</td>
                        <td style="width: 300px;">{fldDstCC}</td>
                </tr>
        
                <tr>
                        <td style="width: 200px;"><strong>Packet-Size</strong></td>
                        <td style="width: 200px;">{fldPktSize}</td>
                </tr>
                
                <tr>
                        <td style="width: 200px;"><strong>Morning</strong></td>
                        <td style="width: 200px;">{fldMorning}</td>
                </tr>
                
                <tr>
                        <td style="width: 150px;"><strong>Afternoon</strong></td>
                        <td style="width: 150px;">{fldAfternoon}</td>
                </tr>
                
                <tr>
                        <td style="width: 150px;"><strong>Evening</strong></td>
                        <td style="width: 150px;">{fldEvening}</td>
                </tr>
                
                <tr>
                        <td style="width: 200px;"><strong>PreDawn</strong></td>
                        <td style="width: 200px;">{fldTwilight}</td>
                </tr>
                
                <tr>
                        <td style="width: 150px;"><strong>Weekend</strong></td>
                        <td style="width: 150px;">{fldWeekend}</td>
                </tr>
                
                <tr>
                        <td style="width: 150px;"><strong>Total</strong></td>
                        <td style="width: 150px;">{fldTotal}</td>
                </tr>
                
                <HR>
                <HR>
	</tbody>
</table>

'''

HTML_END = '''
<p>&nbsp;</p>
</body>

</html>
'''

