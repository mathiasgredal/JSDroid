package tool.entryForAllApks;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.UIManager;

import jxl.Sheet;
import jxl.Workbook;

import org.jvnet.substance.SubstanceLookAndFeel;
import org.jvnet.substance.button.StandardButtonShaper;
import org.jvnet.substance.painter.StandardGradientPainter;
import org.jvnet.substance.skin.BusinessBlueSteelSkin;
import org.jvnet.substance.skin.OfficeSilver2007Skin;
import org.jvnet.substance.title.FlatTitlePainter;
import org.jvnet.substance.watermark.SubstanceStripeWatermark;
import org.jf.dexlib2.dexbacked.raw.HeaderItem;

import soot.G;
import soot.Scene;
import soot.SootClass;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.options.Options;
import tool.Analy.Analysis.AndroidAnalysis;
import tool.GUI.userWindowForAll;
import tool.Result.result2excel;
import tool.Result.result2excelSimple;
import android.R.integer;

import com.test.xmldata.ProcessManifest;

public class EntryForAll { //Entry
	private String apkFileDirectory; //APK fileS directory
	private String androidPlatformLocation; //Android platform path
	private String apkFileLocation; //APK file path
	private ArrayList<String> AllApkFilePathList; //All APK file path list
	private result2excel excel; //Excel
	private String ResultExcelLocation; //Excel path
	public long runningTime;
	public int selectedApkCount;
	public int failedApkCount;
	
    public EntryForAll(String[] args){ //Initialization
    	
		apkFileDirectory=args[0];
		androidPlatformLocation=normalizeAndroidPlatformPath(args[1]);
		AllApkFilePathList=new ArrayList<String>();
		ResultExcelLocation="Results.xls";
		excel=new result2excel();
		excel.initExcel(this.ResultExcelLocation);
	}
    
	public ArrayList<String> getApkFiles(){ //Get APK files, return APK name list
	     
		 File f=new File(this.apkFileDirectory);
		 File[] list=f.listFiles();
		 String filePath,fileName,fileExtension; 
		 ArrayList<String> apkNameList=new ArrayList<String>();
		 for(int i=0;i<list.length;i++)
		 {
			 filePath=list[i].getAbsolutePath(); 
			 fileName=list[i].getName();  
			 int index1=filePath.lastIndexOf(".");
			 int index2=filePath.length();
			 fileExtension=filePath.substring(index1+1,index2);
			 if(fileExtension.equals("apk")){ //If the file is APK
				 this.AllApkFilePathList.add(filePath);
				 apkNameList.add(fileName);
			 }
		 }
	     return apkNameList;
	}
	
	public void AnalyzeAll(ArrayList<Integer> selectedApkIndexList){//Analyze all APKs
        /*
         * Param: Index list of selected APKs  
         */
		selectedApkCount=selectedApkIndexList.size(); //Number of selected APKs
		failedApkCount=0;
		int curIndex; //Current APK index
		String curAppName; //Current APK name
		long start=System.currentTimeMillis(); // Time when it starts 
		for(int i=0;i<selectedApkCount;i++){
			curIndex=selectedApkIndexList.get(i);
			apkFileLocation=AllApkFilePathList.get(curIndex).toString();
			curAppName = deriveAppName(apkFileLocation);
			System.out.println("App count: "+(i+1));
			System.out.println("App path: "+apkFileLocation);
			System.out.println("App name: "+curAppName);
			try {
				validateDexFiles(apkFileLocation);
				String param[] = {"-android-jars",androidPlatformLocation,"-process-dir", apkFileLocation};
				initSoot(param);
				AndroidAnalysis analysis=new AndroidAnalysis(curAppName);
				analysis.Analyze();
				ProcessManifest processMan = new ProcessManifest();
				processMan.loadManifestFile(apkFileLocation);
				System.out.println("FileExported:"+processMan.FileExported);
				System.out.println("HttpExported:"+processMan.HttpExported);
				excel.addOneLine2Excel(curAppName, analysis, processMan,i+1);
				AnalyzeVulnerAndDisplayResults(analysis,processMan);
				if(processMan.HttpsExported){
					System.out.println("??app?????https://???????");
				}
				else {
					System.out.println("??app?????????????https://??????????");
				}
				if(analysis.trust){
					System.out.println("??app????????????????????????");
				}
				else{
					System.out.println("??app?????????????????????????");

				}
			} catch (Exception e) {
				failedApkCount++;
				String failureMessage=describeProcessingFailure(e);
				System.out.println("Skipping app '"+curAppName+"': "+failureMessage);
				excel.addErrorLine2Excel(curAppName, failureMessage, i+1);
			} finally {
				G.v();
				G.reset();
			}
		}
		excel.WriteAll(); //Write all line into excel
		long end=System.currentTimeMillis(); //Time when it ends
	    runningTime=(end-start)/1000; // Running Time(:s)
		System.out.println("It takes "+runningTime+" seconds to analyze all these "+selectedApkCount+" apps");
		if(failedApkCount>0){
			System.out.println("Skipped "+failedApkCount+" app(s) because they could not be processed.");
		}
	}
	
	public void AnalyzeVulnerAndDisplayResults(AndroidAnalysis analysis, ProcessManifest processMan){
		if((analysis.flagPotentialFileVulner==true)&&(processMan.FileExported==true)){
			System.out.println("The app exists File-based cross-zone vulnerability.");
		}
        else{
        	System.out.println("The app does not exist File-based cross-zone vulnerability.");
        }
		if((analysis.flagPotentialUXSSVulner==true)&&(processMan.HttpExported==true)){
			System.out.println("The app exists WebView UXSS vulnerability.");
        }
        else{
        	System.out.println("The app does not exist WebView UXSS vulnerability.");
        }
		if((analysis.flagPotentialInterfaceVulner==true)&&(processMan.FileExported==true||processMan.HttpExported==true)){
			System.out.println("The app exists JavaScript-to-Java interface vulnerability.");
        }
        else{
            System.out.println("The app does not exist JavaScript-to-Java interface vulnerability.");
        }
	}

    public Object[] getResult(int i){//Get results
       /*
        * param: index
        * return: object array of one result
        */
    	Workbook book;
		try {
	    	book = Workbook.getWorkbook(new File(ResultExcelLocation));	
			Sheet sheet=book.getSheet(result2excel.SheetName);
			int cols=sheet.getColumns();
//			Object[] rowData=new Object[cols];
			Object[] rowData=new Object[7];
//			????????????????????????????????????????????0,1,15,17,19??????
			rowData[0]=sheet.getCell(0,i).getContents();
			rowData[1]=sheet.getCell(1,i).getContents();
			rowData[2]=sheet.getCell(15,i).getContents();
			rowData[3]=sheet.getCell(17,i).getContents();
			rowData[4]=sheet.getCell(19,i).getContents();
			rowData[5]=sheet.getCell(22,i).getContents();
			rowData[6]=sheet.getCell(23,i).getContents();
//			for(int j=0;j<cols;j++){
//				rowData[j]=sheet.getCell(j,i).getContents();
//			}
			book.close();
			return rowData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void initSoot(String[] args){ // soot initialization
		/*
		 * Params
		 * args[0,1]: APK file location   
		 * args[2,3]: Path of Android platform 
		 */
//    	Options.v().set_validate(true);
    	String sep=File.pathSeparator;
    	String sootClasspath=this.apkFileLocation+sep+
				new File("lib/jce.jar").getAbsolutePath()+sep+
				new File("lib/tools.jar").getAbsolutePath()+sep+
				new File("lib/android.jar").getAbsolutePath()+sep+
				new File("lib/android-support-v4.jar").getAbsolutePath()+sep+
				new File("bin").getAbsolutePath();
    	Options.v().set_soot_classpath(sootClasspath);
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_output_dir("JimpleOutput");
		Options.v().set_keep_line_number(true);
		Options.v().set_prepend_classpath(true);
	    Options.v().set_allow_phantom_refs(true);
	    applyAndroidJarOption(args[1]);
	    Options.v().set_process_dir(Collections.singletonList(args[3]));
	    Options.v().set_whole_program(true);
		Options.v().set_force_overwrite(true); 
		Scene.v().loadNecessaryClasses();	// Load necessary classes
        CHATransformer.v().transform(); //Call graph
        Scene.v().addBasicClass("java.io.BufferedReader",SootClass.HIERARCHY);
		Scene.v().addBasicClass("java.lang.StringBuilder",SootClass.BODIES);
		Scene.v().addBasicClass("java.util.HashSet",SootClass.BODIES);
		Scene.v().addBasicClass("android.content.Intent",SootClass.BODIES);
		Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES); 
        Scene.v().addBasicClass("com.app.test.CallBack",SootClass.BODIES);		
        Scene.v().addBasicClass("java.io.Serializable",SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.io.Serializable",SootClass.BODIES);
        Scene.v().addBasicClass("android.graphics.PointF",SootClass.SIGNATURES);
        Scene.v().addBasicClass("android.graphics.PointF",SootClass.BODIES);
        Scene.v().addBasicClass("org.reflections.Reflections",SootClass.HIERARCHY);
        Scene.v().addBasicClass("org.reflections.scanners.Scanner",SootClass.HIERARCHY);
        Scene.v().addBasicClass("org.reflections.scanners.SubTypesScanner",SootClass.HIERARCHY);
        Scene.v().addBasicClass("java.lang.ThreadGroup",SootClass.SIGNATURES);
        Scene.v().addBasicClass("com.ironsource.mobilcore.OfferwallManager",SootClass.HIERARCHY);
        Scene.v().addBasicClass("bolts.WebViewAppLinkResolver$2",SootClass.HIERARCHY);
        Scene.v().addBasicClass("com.ironsource.mobilcore.BaseFlowBasedAdUnit",SootClass.HIERARCHY);
        Scene.v().addBasicClass("android.annotation.TargetApi",SootClass.SIGNATURES);
        Scene.v().addBasicClass("com.outfit7.engine.Recorder$VideoGenerator$CacheMgr",SootClass.HIERARCHY);
        Scene.v().addBasicClass("com.alibaba.motu.crashreporter.handler.CrashThreadMsg$",SootClass.HIERARCHY);
        Scene.v().addBasicClass("java.lang.Cloneable",SootClass.HIERARCHY);
        Scene.v().addBasicClass("org.apache.http.util.EncodingUtils",SootClass.SIGNATURES);
        Scene.v().addBasicClass("org.apache.http.protocol.HttpRequestHandlerRegistry",SootClass.SIGNATURES);
        Scene.v().addBasicClass("org.apache.commons.logging.Log",SootClass.SIGNATURES);
        Scene.v().addBasicClass("org.apache.http.params.HttpProtocolParamBean",SootClass.SIGNATURES);
        Scene.v().addBasicClass("org.apache.http.protocol.RequestExpectContinue",SootClass.SIGNATURES);
        Scene.v().loadClassAndSupport("Constants");	
	}

	private String deriveAppName(String apkPath){
		String name=new File(apkPath).getName();
		int dot=name.lastIndexOf(".");
		if(dot>0){
			return name.substring(0,dot);
		}
		return name;
	}

	private String normalizeAndroidPlatformPath(String inputPath){
		File input=new File(inputPath);
		if(input.isDirectory()){
			File directJar=new File(input,"android.jar");
			if(directJar.exists()){
				return directJar.getAbsolutePath();
			}
			File sdkPlatforms=new File(input,"platforms");
			if(sdkPlatforms.exists()&&sdkPlatforms.isDirectory()){
				return sdkPlatforms.getAbsolutePath();
			}
			File bundledPlatform=new File(input,"android--1/android.jar");
			if(bundledPlatform.exists()){
				return bundledPlatform.getAbsolutePath();
			}
		}
		return inputPath;
	}

	private void applyAndroidJarOption(String androidPath){
		File androidFile=new File(androidPath);
		if(androidFile.isFile()&&androidFile.getName().equals("android.jar")){
			Options.v().set_force_android_jar(androidFile.getAbsolutePath());
			return;
		}
		File directJar=new File(androidFile,"android.jar");
		if(directJar.exists()){
			Options.v().set_force_android_jar(directJar.getAbsolutePath());
			return;
		}
		Options.v().set_android_jars(androidPath);
	}

	private void validateDexFiles(String apkPath) throws ApkProcessingException{
		ZipInputStream zipInput=null;
		boolean foundDexFile=false;
		try{
			zipInput=new ZipInputStream(new FileInputStream(apkPath));
			ZipEntry entry;
			while((entry=zipInput.getNextEntry())!=null){
				if(isDexEntry(entry.getName())){
					foundDexFile=true;
					validateDexHeader(entry.getName(), zipInput);
				}
			}
		} catch (IOException e) {
			throw new ApkProcessingException("Could not read APK: "+safeMessage(e), e);
		} finally {
			if(zipInput!=null){
				try {
					zipInput.close();
				} catch (IOException e) {
					System.out.println("Warning: could not close APK file: "+safeMessage(e));
				}
			}
		}
		if(!foundDexFile){
			throw new ApkProcessingException("APK does not contain any classes*.dex files.");
		}
	}

	private boolean isDexEntry(String entryName){
		return entryName.equals("classes.dex") || (entryName.startsWith("classes") && entryName.endsWith(".dex"));
	}

	private void validateDexHeader(String entryName, ZipInputStream zipInput) throws IOException, ApkProcessingException{
		byte[] magic=new byte[8];
		int bytesRead=readFully(zipInput, magic);
		if(bytesRead<magic.length){
			throw new ApkProcessingException(entryName+" has an incomplete dex header.");
		}
		if(!hasDexMagicPrefix(magic)){
			throw new ApkProcessingException(entryName+" is not a valid dex file.");
		}
		if(!HeaderItem.verifyMagic(magic, 0)){
			String version=""+(char)magic[4]+(char)magic[5]+(char)magic[6];
			throw new ApkProcessingException(entryName+" uses dex version "+version+", which is not supported by this JSDroid build's bundled Soot/dexlib.");
		}
	}

	private boolean hasDexMagicPrefix(byte[] magic){
		return magic[0]=='d'&&magic[1]=='e'&&magic[2]=='x'&&magic[3]=='\n'&&magic[7]==0;
	}

	private int readFully(ZipInputStream zipInput, byte[] buffer) throws IOException{
		int total=0;
		while(total<buffer.length){
			int count=zipInput.read(buffer, total, buffer.length-total);
			if(count<0){
				break;
			}
			total+=count;
		}
		return total;
	}

	private String describeProcessingFailure(Exception e){
		if(e instanceof ApkProcessingException){
			return safeMessage(e);
		}
		String message=safeMessage(e);
		return e.getClass().getName()+": "+message;
	}

	private String safeMessage(Exception e){
		if(e.getMessage()==null||e.getMessage().length()==0){
			return e.getClass().getName();
		}
		return e.getMessage();
	}

	private static class ApkProcessingException extends Exception{
		private static final long serialVersionUID = 1L;

		public ApkProcessingException(String message){
			super(message);
		}

		public ApkProcessingException(String message, Throwable cause){
			super(message, cause);
		}
	}
}
