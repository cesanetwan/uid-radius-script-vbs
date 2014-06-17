' Copyright (c) 2011 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
'
' Permission to use, copy, modify, and distribute this software for any
' purpose with or without fee is hereby granted, provided that the above
' copyright notice and this permission notice appear in all copies.

' Alterations to use RADIUS accounting logs/DHCP leases over Kiwi/syslog 
' v5.8
' Gareth Hill

' Changelog:

strVersion = "5.8vbs"

' v5.8
'   * Supports a second pass over DHCP for use in situations wherein the script is executing before a lease is granted to a workstation.
' v5.7
'   * Supports users in the format user@domain
'   * Fixed issue where events triggered with Framed-IP as Calling Station in Windows Event (ie WebAuth) weren't submitting.
' v5.6
'   * Submits script version when submitting to XML API
' v5.5
'   * Support for the XML API proxy by way of flag, modified post data to include source vsys
' v5.1 
'	* Agentless support
' v5.0
'	* DHCP stuff added
' v4.7
'	* Now passes username from Windows Event to script to allow for more precision - requires the scheduled task to be created with further criteria.
'	* Added a flag that allows script to be recursively called to account for possible latency between the log write and windows event; this is experimental and should NOT be enabled by default.
' v4.5
'	* Here there be dragons
'	* Added optimisation to attempt to reduce runtime, at the cost of more system resources; may seperate into flag, likely will be scrapped
' v4.0
'	* Added support for configuration XML File
'	* IAS log compatibility improved; variable set in configuration file
'	* Seperated DTS/IAS into seperate functions
'	* Possible debug flag in config file for future release?
' v3.0
'	* Added IAS log compatibility
' v2.2
'	* Fixed issue with mm/dd/yyyy date format in nps logs; only captures time now
' V2.1
'	* Added support for ignore-user-list
' v2.0
'	* Optimised to process last 500 events only
'	* Removed timestamp-based logic - if only reading last 500 events, not required, simplifies regex, improves efficiency
'	* Removed tail functionality - inefficent

' Script to read a log upon Microsoft's RADIUS service authenticating against a site's AD, and pass the username/IP to the Palo-Alto User-Agent

On Error Resume Next

'//
'//Declaring site-agnostic variables
'//

set xmlHttp = CreateObject("MSXML2.ServerXMLHTTP")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Const SXH_SERVER_CERT_IGNORE_ALL_SERVER_ERRORS = 13056
ptrn = "<Timestamp data_type=\S4\S>.+(\d\d:\d\d:\d\d)\.\d+</Timestamp>.*<User-Name data_type=\S1\S>(.+)</User-Name>.*<Framed-IP-Address data_type=\S3\S>(\d+\.\d+\.\d+\.\d+)</Framed-IP-Address>.*<Acct-Authentic data_type=\S0\S>[^3]</Acct-Authentic>.*<Client-IP-Address data_type=\S3\S>(\d+\.\d+\.\d+\.\d+)" '//Regex Pattern to match in the logs, for NPS
ptrnDHCP= "<Timestamp data_type=\S4\S>.+(\d\d:\d\d:\d\d)\.\d+</Timestamp>.*<User-Name data_type=\S1\S>(.+)</User-Name>.*<Calling-Station-Id data_type=\S1\S>(.+)</Calling-Station-Id>"
strFileName = "IN" & right(year(date()),2) & right("0" & month(date()),2) & right("0" & day(date()),2) & ".log" '//The log name for the date in question
Dim arrExclusions(), aClientIPS(), arrDHCPServer(), arrFoundInScope(), arrMatchedIPAddresses()
Dim strDomain, strLogPath, strLogFormat, strAgentServer, strAgentPort, strDHCPServer, strVsys, blnAgent, strAPIKey, strTimeout, debug, intMacsFound, strMultipass
Dim strStartTime, strEndTime, strProxy, strPostAddr
Set xmlDoc = CreateObject("Microsoft.XMLDOM")
xmlDoc.Async = "False"

If objFSO.FileExists("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml") Then
	xmlDoc.Load("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml")
Else
	CreateDefaultConfig
	xmlDoc.Load("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml")
End If	

LoadConfig

If debug > 0 Then '//Debug flag active, open/create the log, write the opening seperator
	Set objDebugLog = objFSO.OpenTextFile("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDDebug.log", 8, True)
	objDebugLog.writeLine("===================================================================================================================================")
	strStartTime = Now()
	objDebugLog.writeLine("UID Script triggered at " & strStartTime)
End If

If debug > 1 Then
	objDebugLog.writeLine("Capturing arguments...")
End If	

strEventUser = wscript.arguments.item(0)
strCallingStation = wscript.arguments.item(1)

If Err <> 0 Then
	strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
	If debug > 1 Then
		objDebugLog.writeLine(strErrInfo)
	End If
Else
	objDebugLog.writeLine("Script executed with arguments: """ & strEventUser & """ " & strCallingStation)
End If

If debug > 1 Then
	objDebugLog.writeLine("Loading Exclusions...")
End If	

LoadExclusions("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\ignore_user_list.txt")

If Err <> 0 Then
	strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
	If debug > 1 Then
		objDebugLog.writeLine(strErrInfo)
	End If
Else
	objDebugLog.writeLine("Exclusions loaded successfully")
End If

If strLogFormat="DTS" Then
	intLength = LogLength(strLogPath & strFileName)

	If Err <> 0 Then
		strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
		If debug > 1 Then
			objDebugLog.writeLine(strErrInfo)
		End If
	Else
		objDebugLog.writeLine("Log Length: " & intLength)
	End If

	intLineCounter = 0 
	Set objFile = objFSO.OpenTextFile(strLogPath & strFileName)

	If Err <> 0 Then
		strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
		If debug > 1 Then
			objDebugLog.writeLine(strErrInfo)
		End If
	Else
		objDebugLog.writeLine("Opening log: " & strLogPath & strFileName)
	End If

	If debug > 0 Then
		objDebugLog.writeLine("DTS Format processing")
	End If

	ProcessDTSLog

	If debug > 0 Then
		strEndTime = Now()
		objDebugLog.writeLine("UID Script finished execution at " & strEndTime & " Run-time: " & DateDiff("s",strStartTime,strEndTime) & " seconds")
		objDebugLog.writeLine("===================================================================================================================================")
	End If

	objFile.Close '//close off the file
ElseIf strLogFormat="IAS" Then
	intLength = LogLength(strLogPath & strFileName) 

	If Err <> 0 Then
		strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
		If debug > 1 Then
			objDebugLog.writeLine(strErrInfo)
		End If
	Else
		objDebugLog.writeLine("Log Length: " & intLength)
	End If

	intLineCounter = 0
	Set objFile = objFSO.OpenTextFile(strLogPath & strFileName) 

	If Err <> 0 Then
		strErrInfo = "Error: " & Err & " Source: " & Err.Source & " Description: " & Err.Description
		If debug > 1 Then
			objDebugLog.writeLine(strErrInfo)
		End If
	Else
		objDebugLog.writeLine("Opening log: " & strLogPath & strFileName)
	End If

	If debug > 0 Then '//Write basic debug info
		objDebugLog.writeLine("IAS Format Processing")
	End If

	ProcessIASLog

	If debug > 0 Then
		strEndTime = Now()
		objDebugLog.writeLine("UID Script finished execution at " & strEndTime & " Run-time: " & DateDiff("s",strStartTime,strEndTime) & " seconds")
		objDebugLog.writeLine("===================================================================================================================================")
	End If

	objFile.Close
ElseIf strLogFormat="DHCP" Then
	If debug > 0 Then
		strLogLine = "DHCP Lease query for Windows Event User: " & strEventUser & " Calling Station ID: " & strCallingStation & " Querying DHCP Servers: "
		For Each DHCPServer in arrDHCPServer
			strLogLine = strLogLine + DHCPServer + " "
		Next
		objDebugLog.writeLine(strLogLine)
	End If

	ProcessDHCPClients

	If debug > 0 Then
		strEndTime = Now()
		objDebugLog.writeLine("UID Script finished execution at " & strEndTime & " Run-time: " & DateDiff("s",strStartTime,strEndTime) & " seconds")
		objDebugLog.writeLine("===================================================================================================================================")
	End If
End If

'//
'//Takes an XML string, opens a connection to User-Agent, sends XML, closes connection
'//

Function PostToAgent(strUserAgentData)
	On Error Resume Next

	If blnAgent = 1 Then
		sUrl = "https://" & strAgentServer & ":" & strAgentPort & "/"
		xmlHttp.open "put", sUrl, False
	Else
		If strProxy = "1" Then
			sUrl = strPostAddr
		Else
			sUrl = strPostAddr & "/?key=" & strAPIKey & "&type=user-id&action=set&vsys=" & strVsys & "&client=wget&file-name=UID.xml"
		End If
		xmlHttp.open "post", sUrl, False
	End If

	xmlHttp.setRequestHeader "Content-type", "text/xml"
	xmlHttp.setOption 2, 13056

	If debug > 0 Then
		objDebugLog.writeLine("Sending data: " & strUserAgentData & " to " & sUrl)
		Set objMapLog = objFSO.OpenTextFile("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\maplog.log", 8, True)
		objMapLog.writeLine("[" & Date & " " & FormatDateTime(Time, 4) & ":" & Second(Time) & "] " & strUserAgentData)
	End If

	xmlHttp.send(strUserAgentData)
	strResponse = xmlHttp.responseText

	If debug > 0 Then
		objDebugLog.writeLine("Response: " & strResponse)
	End If

	xmlHttp.close
End Function

'//
'//Reads in a file, returns the number of lines within it
'//

Function LogLength(strPath)
	LogLength = 0
	Set objLog = objFSO.OpenTextFile(strPath)
	Do Until objLog.AtEndofStream 
		objLog.SkipLine
		LogLength = LogLength + 1
	Loop
	objLog.Close
End Function

'//
'//Loads users to ignore mappings from.
'//

Function LoadExclusions(strExcPath)
	ExcLength = 0
	Set objExc = objFSO.OpenTextFile(strExcPath)
	Do Until objExc.AtEndofStream 
		Redim Preserve arrExclusions(ExcLength)
		arrExclusions(ExcLength) = Trim(objExc.readLine)
		ExcLength = ExcLength + 1
	Loop
	objExc.Close
End Function

'//
'//Parses DTS log, inspects the data associated with each event, validates, generates XML string, passes to UID
'// 

Function ProcessDTSLog
	Set re = New RegExp
	re.Pattern = ptrn
	re.IgnoreCase = False
	re.Global = True
	On Error Resume Next
	Do Until objFile.AtEndofStream 
		If intLineCounter >= (intLength - 500) Then 
			strLog = objFile.ReadLine() 
			Set Matches = re.Execute(strLog) 
			If Matches.Count > 0 Then 
				set oMatch = Matches(0)
				strTimestamp = oMatch.subMatches(0)
				strUser = oMatch.subMatches(1)
				strAddress = oMatch.subMatches(2)
				strClientIP = oMatch.subMatches(3)

				If InStr(strUser, "\") > 0 Then 
					strUser = Right(strUser, ((Len(strUser))-(InStr(strUser, "\"))))
				End If

				If InStr(strUser, "@") > 0 Then                                                                  
                			strUser = Left(strUser, (InStr(strUser, "@"))-1)
				End If

				If InStr(strEventUser, "\") > 0 Then
					strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
				End If

				If InStr(strEventUser, "@") > 0 Then
                			strEventUser = Left(strEventUser, (InStr(strEventUser, "@"))-1)
				End If	

				If strUser = strEventUser Then
					If debug = 2 Then
						objDebugLog.writeLine("User matched against RADIUS log event")
					End If

					If UBound(Filter(arrExclusions, strUser, True, 1)) <= -1 Then
						If debug = 2 Then
							objDebugLog.writeLine("User not excluded")
						End If

						'//If DateDiff("n",FormatDateTime(strTimestamp),Time) <= 2 Then 
							If UBound(Filter(aClientIPs, strClientIP, True, 0)) > -1 Then 
								If debug = 2 Then
									objDebugLog.writeLine("User from valid WLC")
								End If

								If InStr(strUser, "host/") = 0 Then
									If debug = 2 Then
										objDebugLog.writeLine("Not machine auth event")
									End If

									If strProxy = "1" Then
                                                                                strXMLLine = "<uid-message><version>1.0</version><scriptv>" & strVersion & "</scriptv><type>update</type><payload><login>"
                                                                        Else
                                                                                strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
                                                                        End If

									If blnAgent = 1 Then
										strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """/>"
									Else
										If strProxy = "1" Then
						                    			strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """ vsys=""" & strVsys & """/>"
								                Else
											strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """/>"
							                	End If
									End If

									strXMLLine = strXMLLine & "</login></payload></uid-message>"
									PostToAgent(strXMLLine)
								End If
							'//End If
						End If
					End If
				End If
			End If
		Else
			objFile.SkipLine
			intLineCounter = intLineCounter + 1
		End If
	Loop
End Function

'//
'//Parses IAS log, inspects the data associated with each event, validates, generates XML string, passes to UID
'// 

Function ProcessIASLog
	On Error Resume Next
	Do Until objFile.AtEndofStream 
		If intLineCounter >= (intLength - 500) Then 
			strLog = objFile.ReadLine()
			arrIASAttributes = Split(strLog, ",")
			strNotSureWhatThisIs = arrIASAttributes(6)
			strAcctAuth = arrIASAttributes(19)
			If strNotSureWhatThisIs = "5" Then
				If strAcctAuth<>"3" Then
					strTimestamp = arrIASAttributes(3)
					strUser = arrIASAttributes(1)
					strAddress = arrIASAttributes(11)
					strClientIP = arrIASAttributes(9)

					If InStr(strUser, "\") > 0 Then 
						strUser = Right(strUser, ((Len(strUser))-(InStr(strUser, "\"))))
					End If

					If InStr(strUser, "@") > 0 Then                                                                  
                				strUser = Left(strUser, (InStr(strUser, "@"))-1)
					End If

					If InStr(strEventUser, "\") > 0 Then
						strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
					End If

					If InStr(strEventUser, "@") > 0 Then
                				strEventUser = Left(strEventUser, (InStr(strEventUser, "@"))-1)
					End If	

					If strUser = strEventUser Then
						If debug = 2 Then
							objDebugLog.writeLine("User matched against RADIUS log event")
						End If

						If UBound(Filter(arrExclusions, strUser, True, 1)) <= -1 Then
							If debug = 2 Then
								objDebugLog.writeLine("User not excluded")
							End If
							'//If DateDiff("n",FormatDateTime(strTimestamp),Time) <= 2 Then 
								If UBound(Filter(aClientIPs, strClientIP, True, 0)) > -1 Then 
									If debug = 2 Then
										objDebugLog.writeLine("User from valid WLC")
									End If

									If InStr(strUser, "host/") = 0 Then 
										If debug = 2 Then
											objDebugLog.writeLine("Not machine auth event")
										End If

										If strProxy = "1" Then
                        	                                                        strXMLLine = "<uid-message><version>1.0</version><scriptv>" & strVersion & "</scriptv><type>update</type><payload><login>"
                	                                                        Else
        	                                                                        strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
	                                                                        End If

										If blnAgent = 1 Then
											strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """/>"
										Else
											If strProxy = "1" Then
									                        strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """ vsys=""" & strVsys & """/>"
						                    			Else
									                        strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """/>"
						                    			End If
										End If

										strXMLLine = strXMLLine & "</login></payload></uid-message>"
										PostToAgent(strXMLLine) 
									End If
								End If
							'//End If
						End If
					End If
				End If
			End If
		Else
			objFile.SkipLine
			intLineCounter = intLineCounter + 1 '//increment the counter
		End If
	Loop
End Function

'//
'//Searches all existing DHCP leases for all scopes for CallingStationID, resolves to IP, passes to agent
'//

Function ProcessDHCPClients
	On Error Resume Next

	If InStr(strEventUser, "\") > 0 Then
		strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
	End If

	If InStr(strEventUser, "@") > 0 Then
                strEventUser = Left(strEventUser, (InStr(strEventUser, "@"))-1)
	End If	

	If InStr(strEventUser, "$") = 0 Then
		If InStr(strEventUser, "host/") = 0 Then
			If debug = 2 Then
				objDebugLog.writeLine("Not machine auth event")
			End If

			Set oRe=New RegExp
			oRe.Global=True
			oRe.Pattern= "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
			Set o=oRe.Execute(strCallingStation)

			If o.count=1 Then
				If debug = 2 Then
					objDebugLog.writeLine("Calling station is IP, no DHCP lookup required")
				End If

				Redim Preserve arrMatchedIPAddresses(0)
				arrMatchedIPAddresses(0) = strCallingStation
			Else
				Set oRe=New RegExp 
				Set oShell = CreateObject("WScript.Shell") 
				oRe.Global=True
				oRe.Pattern= "\s(\d+\.\d+\.\d+\.\d+)\s*-\s\d+\.\d+\.\d+\.\d+\s*-Active"
				intMacsFound = 0

				Redim Preserve arrMatchedIPAddresses(-1)

				For Each DHCPServer in arrDHCPServer
					strDHCPServer = DHCPServer

					If debug = 2 Then
						objDebugLog.writeLine("DHCP Server: " + strDHCPServer)
						objDebugLog.writeLine("Defining scopes:")
					End If

					Set oScriptExec = oShell.Exec("netsh dhcp server \\" & strDHCPServer & " show scope") 
					Set o=oRe.Execute(oScriptExec.StdOut.ReadAll) 

					For i=0 To o.Count-1
 						Redim Preserve arrScopes(i)
 						arrScopes(i) = o(i).SubMatches(0)

						If debug = 2 Then
							objDebugLog.writeLine("       " & arrScopes(i))
						End If
					Next

					CleanMac strCallingStation

					If debug = 2 Then
						objDebugLog.writeLine("Searching DHCP leases for " & strCallingStation)
					End If

					For Each scope in arrScopes
						If debug = 2 Then
							objDebugLog.writeLine("       " & "SCOPE: " & scope)
						End If

    						FindMac scope, strCallingStation
					Next
				Next
			End If

			If UBound(arrMatchedIPAddresses) > -1 Then
				For Each strAddress in arrMatchedIPAddresses
					If strProxy = "1" Then
	                                       strXMLLine = "<uid-message><version>1.0</version><scriptv>" & strVersion & "</scriptv><type>update</type><payload><login>"
                                        Else
                                               strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
                                        End If


					If blnAgent = 1 Then
						    strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """/>"
					Else
						If strProxy = "1" Then
							strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """ vsys=""" & strVsys & """/>"
						Else
							strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """/>"
						End If
					End If

					strXMLLine = strXMLLine & "</login></payload></uid-message>"
					PostToAgent(strXMLLine) '//Send the relevant UID details to User-Agent
				Next
			Else
				If strMultipass = 0 Then
					If debug > 0 Then
						objDebugLog.writeLine("MAC not found, no data posted")
					End If
				Else
					If debug > 0 Then
						objDebugLog.writeLine("Second DHCP Pass")
					End If

					Set oRe=New RegExp 
					Set oShell = CreateObject("WScript.Shell") 
					oRe.Global=True
					oRe.Pattern= "\s(\d+\.\d+\.\d+\.\d+)\s*-\s\d+\.\d+\.\d+\.\d+\s*-Active"
					intMacsFound = 0

					For Each DHCPServer in arrDHCPServer
						strDHCPServer = DHCPServer

						If debug = 2 Then
							objDebugLog.writeLine("DHCP Server: " + strDHCPServer)
							objDebugLog.writeLine("Defining scopes:")
						End If

						Set oScriptExec = oShell.Exec("netsh dhcp server \\" & strDHCPServer & " show scope") 
						Set o=oRe.Execute(oScriptExec.StdOut.ReadAll) 

						For i=0 To o.Count-1
 							Redim Preserve arrScopes(i)
 							arrScopes(i) = o(i).SubMatches(0)

							If debug = 2 Then
								objDebugLog.writeLine("       " & arrScopes(i))
							End If
						Next

						CleanMac strCallingStation

						If debug = 2 Then
							objDebugLog.writeLine("Searching DHCP leases for " & strCallingStation)
						End If

						For Each scope in arrScopes
							If debug = 2 Then
								objDebugLog.writeLine("       " & "SCOPE: " & scope)
							End If

    							FindMac scope, strCallingStation
						Next
					Next

					If UBound(arrMatchedIPAddresses) >= -1 Then
						For Each strAddress in arrMatchedIPAddresses
							If strProxy = "1" Then
	                        	strXMLLine = "<uid-message><version>1.0</version><scriptv>" & strVersion & "</scriptv><type>update</type><payload><login>"
                            Else
                            	strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
                            End If

							If blnAgent = 1 Then
								strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """/>"
							Else
								If strProxy = "1" Then
									strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """ vsys=""" & strVsys & """/>"
								Else
									strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""" & strTimeout & """/>"
								End If
							End If

							strXMLLine = strXMLLine & "</login></payload></uid-message>"
							PostToAgent(strXMLLine) '//Send the relevant UID details to User-Agent
						Next
					Else
						If debug > 0 Then
							objDebugLog.writeLine("MAC not found, no data posted")
						End If
					End If
				End If
			End If
		Else
			If debug = 2 Then
				objDebugLog.writeLine("Machine auth event")
			End If
		End If
	Else
		If debug = 2 Then
			objDebugLog.writeLine("Machine auth event")
		End If
	End If
End Function

'//
'//Loads site-specific variables from UIDConfig.xml
'//

Function LoadConfig
	Set colItem = xmlDoc.selectNodes("/user-id-script-config/wireless-lan-controllers/wlc")
	count = 0
	For Each objItem in colItem
		Redim Preserve aClientIPs(count)
		aClientIPs(count) = objItem.text
		count = count + 1
	Next
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/domain")
	strDomain = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/LogPath")
	strLogPath = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/AgentServer")
	strAgentServer = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/AgentPort")
	strAgentPort = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/LogFormat")
	strLogFormat = objItem.text
	Set colItem = xmlDoc.selectNodes("/user-id-script-config/DHCPServer")
	count = 0
	For Each objItem in colItem
		Redim Preserve arrDHCPServer(count)
		arrDHCPServer(count) = objItem.text
		count = count + 1
	Next
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/VSYS")
	strVsys = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Key")
	strAPIKey = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Agent")
	blnAgent = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Timeout")
	strTimeout = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Debug")
	debug = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Proxy")
	strProxy = objItem.text
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/PostAddr")
	strPostAddr = objItem.text
	count = 0
	Set objItem = xmlDoc.selectSingleNode("/user-id-script-config/Multipass")
	strMultipass = objItem.text
End Function

'//
'//Searches all DHCP leases within a scope for a mac address, returns the IP associated, otherwise returns "Fail"
'//

Function FindMac(strScope, strMac)
	strIP = ""
	intIpsFound = 0
	Dim IPsFound()
	Set oShell = CreateObject("WScript.Shell") 
	Set oRe2=New RegExp
	oRe2.Global=True
	oRe2.Pattern= "(\d+\.\d+\.\d+\.\d+)\s*-\s\d+\.\d+\.\d+\.\d+\s*-\s*(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
	Set oScriptExec = oShell.Exec("netsh dhcp server \\" & strDHCPServer & " scope " & strScope & " show clients")
      	Do Until oScriptExec.StdOut.AtEndOfStream  
    		strTemp = oScriptExec.StdOut.ReadLine 
		set p = oRe2.Execute(strTemp)

		If p.Count > 0 Then
			strMacComp = p(0).SubMatches(1)
			CleanMac strMacComp

			If debug = 2 Then
				objDebugLog.writeLine("       " & "       " & "MAC: " & strMacComp)
			End If

			If strMac = strMacComp Then
                		strIP = p(0).SubMatches(0)

				If debug = 2 Then
					objDebugLog.writeLine("       " & "       " & "MAC found, matched IP: " & strIP)
				End If

				If debug = 1 Then
					objDebugLog.writeLine("MAC found, matched IP: " & strIP)
				End If

				Redim Preserve arrMatchedIPAddresses(intMacsFound)
				arrMatchedIPAddresses(intMacsFound) = strIP
				intMacsFound = intMacsFound + 1
			End If
		End If
      	Loop
End Function

'//
'//Takes a mac, casts it to lower case and removes seperators for comparison purposes
'//

Function CleanMac(strMac)
	strMac = Replace(strMac, "-", "")
	strMac = Replace(strMac, ".", "")
	strMac = Replace(strMac, ":", "")
	strMac = LCase(strMac)
End Function

'//
'//Creates a UIDConfig file with default parameters
'//

Function CreateDefaultConfig
	Set wshShell = WScript.CreateObject( "WScript.Shell" )
	Set objCFG = xmlDoc.createElement("user-id-script-config")
	xmlDoc.appendChild objCFG
	Set objIntro = xmlDoc.createProcessingInstruction ("xml","version='1.0' encoding='UTF-8'")  
	xmlDoc.insertBefore objIntro,xmlDoc.childNodes(0)
	Set objWLCs = xmlDoc.createElement("wireless-lan-controllers") 
	objCFG.appendChild objWLCs
	Set objWLC = xmlDoc.createElement("wlc")
	objWLC.text = "1.1.1.1"
	objWLCs.appendChild objWLC
	Set objDomain = xmlDoc.createElement("domain")
	strUserDomain = wshShell.ExpandEnvironmentStrings( "%USERDOMAIN%" )
	strUserDomain = UCase(strUserDomain)
	objDomain.text = strUserDomain
	objCFG.appendChild objDomain
	Set objLogPath = xmlDoc.createElement("LogPath")
	objLogPath.text = "C:\Windows\System32\LogFiles\"
	objCFG.appendChild objLogPath
	Set objLogFormat = xmlDoc.createElement("LogFormat")
	objLogFormat.text = "DHCP"
	objCFG.appendChild objLogFormat
	Set objAgentServer = xmlDoc.createElement("AgentServer")
	objAgentServer.text = "127.0.0.1"
	objCFG.appendChild objAgentServer
	Set objAgentPort = xmlDoc.createElement("AgentPort")
	objAgentPort.text = "5006"
	objCFG.appendChild objAgentPort
	Set objDebug = xmlDoc.createElement("Debug")
	objDebug.text = "0"
	objCFG.appendChild objDebug
	Set objDHCPServer = xmlDoc.createElement("DHCPServer")
	strComputerName = wshShell.ExpandEnvironmentStrings( "%ComputerName%" )
	objDHCPServer.text = strComputerName
	objCFG.appendChild objDHCPServer
	Set objAgent = xmlDoc.createElement("Agent")
	objAgent.text = "1"
	objCFG.appendChild objAgent
	Set objKey = xmlDoc.createElement("Key")
	objKey.text = "key"
	objCFG.appendChild objKey
	Set objTimeout = xmlDoc.createElement("Timeout")
	objTimeout.text = "120"
	objCFG.appendChild objTimeout
	Set objVsys = xmlDoc.createElement("VSYS")
	objVsys.text = "vsys21"
	objCFG.appendChild objVsys
	Set objAPI = xmlDoc.createElement("Proxy")
	objAPI.text = "0"
	objCFG.appendChild objAPI
	Set objPostAddr = xmlDoc.createElement("PostAddr")
	objPostAddr.text = "https://cefilter-api.cesa.catholic.edu.au/api/mapping"
	objCFG.appendChild objPostAddr
	Set objMultipass = xmlDoc.createElement("Multipass")
	objMultipass.text = "0"
	objCFG.appendChild objMultipass
	xmlDoc.Save "C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml"
End Function
