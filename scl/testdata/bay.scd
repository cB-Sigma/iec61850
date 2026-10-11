<?xml version="1.0" encoding="UTF-8"?>
<!-- Test system of this module (Apache-2.0, written for it): a bay controller with data sets,
     report, log, GOOSE and sampled value control blocks, a protection IED subscribing to its
     GOOSE and an HMI client. Names, addresses and values are made up. -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tst="urn:example:scl-test" version="2007" revision="C" release="5">
	<Header id="Test bay 7" toolID="hand written" uuid="0b4e7d1a-6a3c-4f1e-9d52-2f8c1a7e3b10" version="1" revision="2"/>
	<Communication>
		<SubNetwork name="StationBus" type="8-MMS">
			<BitRate unit="b/s" multiplier="M">100</BitRate>
			<ConnectedAP iedName="BAY7CTRL" apName="P1">
				<Address>
					<P type="IP">192.0.2.17</P>
					<P type="IP-SUBNET">255.255.255.0</P>
					<P type="IP-GATEWAY">192.0.2.1</P>
					<P type="OSI-TSEL">0001</P>
					<P type="OSI-PSEL">00000001</P>
					<P type="OSI-SSEL">0001</P>
				</Address>
				<GSE ldInst="CTRL" cbName="Interlock">
					<Address>
						<P type="MAC-Address">01-0C-CD-01-07-10</P>
						<P type="APPID">0710</P>
						<P type="VLAN-ID">00A</P>
						<P type="VLAN-PRIORITY">5</P>
					</Address>
					<MinTime unit="s" multiplier="m">2</MinTime>
					<MaxTime unit="s" multiplier="m">2000</MaxTime>
				</GSE>
				<SMV ldInst="CTRL" cbName="BusVolts">
					<Address>
						<P type="MAC-Address">01-0C-CD-04-07-20</P>
						<P type="APPID">4720</P>
						<P type="VLAN-ID">00B</P>
						<P type="VLAN-PRIORITY">6</P>
					</Address>
				</SMV>
			</ConnectedAP>
			<ConnectedAP iedName="BAY7PROT" apName="P1">
				<Address>
					<P type="IP">192.0.2.18</P>
					<P type="IP-SUBNET">255.255.255.0</P>
				</Address>
			</ConnectedAP>
			<ConnectedAP iedName="HMI2" apName="P1"/>
		</SubNetwork>
	</Communication>
	<IED name="BAY7CTRL" manufacturer="Example Works" type="bay controller" configVersion="2.1" originalSclVersion="2007" originalSclRevision="C" originalSclRelease="5">
		<tst:note>kept on export</tst:note>
		<Private type="tst-tool">opaque <tst:y b="2"/></Private>
		<Services nameLength="64">
			<DynAssociation max="4"/>
			<GetDirectory/>
			<GetDataObjectDefinition/>
			<DataSetDirectory/>
			<ConfDataSet max="8" maxAttributes="40"/>
			<ReadWrite/>
			<ConfReportControl max="12" bufConf="true"/>
			<GetCBValues/>
			<ConfLogControl max="2"/>
			<GSESettings cbName="Conf" datSet="Conf" appID="Conf"/>
			<GOOSE max="3"/>
			<SMVsc max="1"/>
			<FileHandling/>
		</Services>
		<AccessPoint name="P1">
			<Server>
				<Authentication none="true"/>
				<LDevice inst="CTRL">
					<LN0 lnClass="LLN0" inst="" lnType="T_LLN0">
						<DataSet name="Switches">
							<FCDA ldInst="CTRL" lnClass="CSWI" lnInst="1" doName="Pos" fc="ST"/>
							<FCDA ldInst="CTRL" lnClass="CSWI" lnInst="2" doName="Pos" fc="ST"/>
						</DataSet>
						<DataSet name="Volts">
							<FCDA ldInst="CTRL" lnClass="MMXU" lnInst="1" doName="PhV.phsB" daName="cVal.mag.f" fc="MX"/>
						</DataSet>
						<DataSet name="Mixed">
							<FCDA ldInst="CTRL" lnClass="MMXU" lnInst="1" doName="A" fc="MX"/>
							<FCDA ldInst="CTRL" lnClass="MMXU" lnInst="1" doName="PhV.phsB" daName="cVal" fc="MX"/>
							<FCDA ldInst="CTRL" lnClass="PTOC" lnInst="1" doName="TmACrv" daName="crvPts(1).yVal" fc="SP" ix="1"/>
						</DataSet>
						<ReportControl name="SwitchRpt" rptID="BAY7Switches" datSet="Switches" confRev="2">
							<TrgOps dchg="true" qchg="true" gi="true"/>
							<OptFields reasonCode="true"/>
							<RptEnabled max="3">
								<ClientLN iedName="HMI2" apRef="P1" ldInst="none" lnClass="IHMI" lnInst="1"/>
							</RptEnabled>
						</ReportControl>
						<ReportControl name="VoltsBuf" datSet="Volts" confRev="7" buffered="true" intgPd="5000" bufTime="50">
							<TrgOps dchg="true" period="true"/>
							<OptFields seqNum="true" timeStamp="true" entryID="true" dataRef="true"/>
						</ReportControl>
						<LogControl name="SwitchLog" datSet="Switches" logName="CTRL">
							<TrgOps dchg="true" qchg="true" gi="true"/>
						</LogControl>
						<DOI name="Mod"><DAI name="ctlModel"><Val>status-only</Val></DAI></DOI>
						<Log/>
						<GSEControl name="Interlock" datSet="Switches" appID="BAY7CTRL/Interlock" confRev="4">
							<IEDName apRef="P1">BAY7PROT</IEDName>
						</GSEControl>
						<SampledValueControl name="BusVolts" datSet="Volts" smvID="BAY7Volts" smpRate="80" nofASDU="1" confRev="1">
							<IEDName apRef="P1">BAY7PROT</IEDName>
							<SmvOpts refreshTime="true" sampleSynchronized="true"/>
						</SampledValueControl>
						<SettingControl numOfSGs="3" actSG="2"/>
					</LN0>
					<LN lnClass="CSWI" inst="1" lnType="T_CSWI"/>
					<LN lnClass="CSWI" inst="2" lnType="T_CSWI"/>
					<LN lnClass="MMXU" inst="1" lnType="T_MMXU">
						<DOI name="TotW">
							<SDI name="sVC">
								<DAI name="scaleFactor"><Val>0.5</Val></DAI>
								<DAI name="offset"><Val>10</Val></DAI>
							</SDI>
						</DOI>
					</LN>
					<LN lnClass="PTOC" inst="1" lnType="T_PTOC">
						<DOI name="TmACrv">
							<SDI name="crvPts" ix="0">
								<DAI name="xVal"><Val>1.5</Val></DAI>
								<DAI name="yVal"><Val>40</Val></DAI>
							</SDI>
							<SDI name="crvPts" ix="1">
								<DAI name="xVal"><Val>6</Val></DAI>
								<DAI name="yVal"><Val>4.5</Val></DAI>
							</SDI>
						</DOI>
					</LN>
				</LDevice>
			</Server>
		</AccessPoint>
	</IED>
	<IED name="BAY7PROT">
		<Services><GOOSE max="2"/><ClientServices goose="true" sv="true"/></Services>
		<AccessPoint name="P1">
			<Server>
				<Authentication/>
				<LDevice inst="PROT">
					<LN0 lnClass="LLN0" inst="" lnType="T_LLN0"/>
					<LN lnClass="PTOC" inst="1" lnType="T_PTOC">
						<Inputs>
							<ExtRef iedName="BAY7CTRL" ldInst="CTRL" lnClass="CSWI" lnInst="1" doName="Pos" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcCBName="Interlock" intAddr="blk1"/>
						</Inputs>
					</LN>
				</LDevice>
			</Server>
		</AccessPoint>
	</IED>
	<IED name="HMI2">
		<Services><ClientServices unbufReport="true" bufReport="true"/></Services>
		<AccessPoint name="P1">
			<LN lnClass="IHMI" inst="1" lnType="T_IHMI"/>
		</AccessPoint>
	</IED>
	<DataTypeTemplates>
		<LNodeType id="T_LLN0" lnClass="LLN0">
			<DO name="Mod" type="T_ENC_Mod"/>
			<DO name="Beh" type="T_ENS_Beh"/>
			<DO name="Health" type="T_ENS_Health"/>
			<DO name="NamPlt" type="T_LPL"/>
		</LNodeType>
		<LNodeType id="T_CSWI" lnClass="CSWI">
			<DO name="Beh" type="T_ENS_Beh"/>
			<DO name="Pos" type="T_DPC"/>
		</LNodeType>
		<LNodeType id="T_MMXU" lnClass="MMXU">
			<DO name="Beh" type="T_ENS_Beh"/>
			<DO name="A" type="T_WYE"/>
			<DO name="PhV" type="T_WYE"/>
			<DO name="TotW" type="T_MV"/>
		</LNodeType>
		<LNodeType id="T_PTOC" lnClass="PTOC">
			<DO name="Beh" type="T_ENS_Beh"/>
			<DO name="Str" type="T_ACD"/>
			<DO name="Op" type="T_ACT" transient="true"/>
			<DO name="TmACrv" type="T_CSG"/>
		</LNodeType>
		<LNodeType id="T_IHMI" lnClass="IHMI">
			<DO name="Beh" type="T_ENS_Beh"/>
		</LNodeType>
		<DOType id="T_ENC_Mod" cdc="ENC">
			<DA name="stVal" fc="ST" dchg="true" bType="Enum" type="T_Beh"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
			<DA name="ctlModel" fc="CF" dchg="true" bType="Enum" type="T_CtlModel"><Val>status-only</Val></DA>
		</DOType>
		<DOType id="T_ENS_Beh" cdc="ENS">
			<DA name="stVal" fc="ST" dchg="true" bType="Enum" type="T_Beh"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
		</DOType>
		<DOType id="T_ENS_Health" cdc="ENS">
			<DA name="stVal" fc="ST" dchg="true" bType="Enum" type="T_Health"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
		</DOType>
		<DOType id="T_LPL" cdc="LPL">
			<DA name="vendor" fc="DC" bType="VisString255"><Val>Example Works</Val></DA>
			<DA name="swRev" fc="DC" bType="VisString255"><Val>2.1.0</Val></DA>
			<DA name="configRev" fc="DC" bType="VisString255"><Val>7</Val></DA>
			<DA name="ldNs" fc="EX" bType="VisString255"><Val>IEC 61850-7-4:2007B</Val></DA>
		</DOType>
		<DOType id="T_DPC" cdc="DPC">
			<DA name="stVal" fc="ST" dchg="true" bType="Dbpos"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
			<DA name="ctlModel" fc="CF" bType="Enum" type="T_CtlModel"><Val>direct-with-normal-security</Val></DA>
		</DOType>
		<DOType id="T_CMV" cdc="CMV">
			<DA name="cVal" fc="MX" dchg="true" bType="Struct" type="T_Vector"/>
			<DA name="q" fc="MX" qchg="true" bType="Quality"/>
			<DA name="t" fc="MX" bType="Timestamp"/>
		</DOType>
		<DOType id="T_WYE" cdc="WYE">
			<SDO name="phsA" type="T_CMV"/>
			<SDO name="phsB" type="T_CMV"/>
			<SDO name="phsC" type="T_CMV"/>
		</DOType>
		<DOType id="T_MV" cdc="MV">
			<DA name="mag" fc="MX" dchg="true" bType="Struct" type="T_AV"/>
			<DA name="q" fc="MX" qchg="true" bType="Quality"/>
			<DA name="t" fc="MX" bType="Timestamp"/>
			<DA name="units" fc="CF" bType="Struct" type="T_Unit"/>
			<DA name="sVC" fc="CF" bType="Struct" type="T_SVC"/>
		</DOType>
		<DOType id="T_ACD" cdc="ACD">
			<DA name="general" fc="ST" dchg="true" bType="BOOLEAN"/>
			<DA name="dirGeneral" fc="ST" dchg="true" bType="Enum" type="T_Dir"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
		</DOType>
		<DOType id="T_ACT" cdc="ACT">
			<DA name="general" fc="ST" dchg="true" bType="BOOLEAN"/>
			<DA name="q" fc="ST" qchg="true" bType="Quality"/>
			<DA name="t" fc="ST" bType="Timestamp"/>
		</DOType>
		<DOType id="T_CSG" cdc="CSG">
			<DA name="pointZ" fc="SP" bType="FLOAT32"/>
			<DA name="numPts" fc="SP" bType="INT16U"><Val>2</Val></DA>
			<DA name="crvPts" fc="SP" bType="Struct" type="T_Point" count="numPts"/>
		</DOType>
		<DAType id="T_AV"><BDA name="f" bType="FLOAT32"/></DAType>
		<DAType id="T_Vector"><BDA name="mag" bType="Struct" type="T_AV"/><BDA name="ang" bType="Struct" type="T_AV"/></DAType>
		<DAType id="T_Unit"><BDA name="SIUnit" bType="Enum" type="T_SIUnit"><Val>W</Val></BDA><BDA name="multiplier" bType="Enum" type="T_Multiplier"><Val>k</Val></BDA></DAType>
		<DAType id="T_SVC"><BDA name="scaleFactor" bType="FLOAT32"/><BDA name="offset" bType="FLOAT32"/></DAType>
		<DAType id="T_Point"><BDA name="xVal" bType="FLOAT32"/><BDA name="yVal" bType="FLOAT32"/></DAType>
		<EnumType id="T_Beh"><EnumVal ord="1">on</EnumVal><EnumVal ord="2">on-blocked</EnumVal><EnumVal ord="3">test</EnumVal><EnumVal ord="4">test/blocked</EnumVal><EnumVal ord="5">off</EnumVal></EnumType>
		<EnumType id="T_Health"><EnumVal ord="1">Ok</EnumVal><EnumVal ord="2">Warning</EnumVal><EnumVal ord="3">Alarm</EnumVal></EnumType>
		<EnumType id="T_CtlModel"><EnumVal ord="0">status-only</EnumVal><EnumVal ord="1">direct-with-normal-security</EnumVal><EnumVal ord="2">sbo-with-normal-security</EnumVal><EnumVal ord="3">direct-with-enhanced-security</EnumVal><EnumVal ord="4">sbo-with-enhanced-security</EnumVal></EnumType>
		<EnumType id="T_Dir"><EnumVal ord="0">unknown</EnumVal><EnumVal ord="1">forward</EnumVal><EnumVal ord="2">backward</EnumVal><EnumVal ord="3">both</EnumVal></EnumType>
		<EnumType id="T_SIUnit"><EnumVal ord="38">W</EnumVal><EnumVal ord="29">V</EnumVal><EnumVal ord="5">A</EnumVal></EnumType>
		<EnumType id="T_Multiplier"><EnumVal ord="0"></EnumVal><EnumVal ord="3">k</EnumVal></EnumType>
	</DataTypeTemplates>
</SCL>
