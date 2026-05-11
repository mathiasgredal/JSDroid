package tool.Analy.Analysis;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;

import android.R.id;
import android.R.integer;
import android.nfc.cardemulation.OffHostApduService;
import soot.Body;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.IfStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.AssignStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Sources;
import soot.tagkit.Tag;
import soot.toolkits.graph.UnitGraph;
import soot.util.Chain;
import tool.Analy.MethodAnalysis.InterMethodAnalysis;
import tool.Result.result2excel;

public class AndroidAnalysis extends BasicAnalysis{

	public boolean flagEnableJS;// app enables JS or not
	public boolean flagUseLocalPattern;// app uses the first way or not
	public boolean flagUseRemotePattern;// app uses the second way or not
	public boolean flagUseInterfacePattern;// app uses the third way or not
	public boolean flagUseCallbackPattern;// app uses the fourth way or not
	public int countLocalPattern;//the count of the first way
	public int countRemotePattern;//the count of the second way
	public int countInterfacePattern;//the count of the third way
	public int countCallbackPattern;//the count of the fourth way
	public int countV1;
	public int countV2;
	public int countV3;
    public int countJSInterfaceWithoutAnnotations;//the count of the JSinterface without annotation
    public int countExposedJSInterface;//the count of exposed JS interface
    public boolean flagSetAllowFileAccess;//app allows JS to access file
    public boolean flagSetAllowHttpAccess;//app allows JS to access http
    public boolean flagExposedNoJSInterface;
    public boolean flagPotentialFileVulner;//whether an app exists file:// vulnerability
    public boolean flagPotentialUXSSVulner;//whether an app exists WebView UXSS vulnerability
    public boolean flagWebViewNavigation;//whether an app exists navigable WebView
    public int countWVhasNavigation;//the count of webview which has navigation ability
    public boolean flagPotentialInterfaceVulner;//whether an app exists the JS-to-Java interface vulnerability
    boolean flagChangePattern;
    public ArrayList<String> JSInterfaceName;//JS interface name list
    public ArrayList<String> RemovedJSInterfaceName;//JS interface name list that has been removed
    public String AppName;//app name
    public int LinesofCode;//the count of code lines
    int Lines;//line in excel
    public int countLocalAndRemotePattern;
    public boolean trust;

  
	

    
    
	public AndroidAnalysis(String appName){
		
		super();
		flagEnableJS = false;
		flagUseLocalPattern = false;
		flagUseRemotePattern = false;
		flagUseInterfacePattern = false;
		flagUseCallbackPattern = false;
		countLocalPattern=0;
		countRemotePattern=0;
		countInterfacePattern=0;
		countCallbackPattern=0;
		countWVhasNavigation=0;
		countJSInterfaceWithoutAnnotations=0;
		countV1=0;
		countV2=0;
		countV3=0;
		LinesofCode=0;
		flagChangePattern=true;
		flagSetAllowFileAccess=true;
		flagSetAllowHttpAccess=true;
		flagExposedNoJSInterface=false;
		flagPotentialFileVulner=false;
		flagPotentialUXSSVulner=false;
		flagWebViewNavigation=false;
	    countWVhasNavigation=0;
		JSInterfaceName=new ArrayList<String>();
		RemovedJSInterfaceName=new ArrayList<String>();
		countExposedJSInterface=0;
	    flagPotentialInterfaceVulner=false;
		AppName=appName;
		countLocalAndRemotePattern=0;
		trust=false;
		
	}
	
    public  void Analyze(){//Start analysis
		
		System.out.println("---------------------------Analysis Begin---------------------------");
		UseJS(classesChain);
		if(flagEnableJS==true){
			System.out.println("The app uses JS");
		    AnalyseAllClasses(classesChain);
		}
		else{
			System.out.println("The app does not use JS");
		}
	    PrintResult(); //Analyze interfaces and print results
//	    Excel.addOneLine2Excel(AppName,this,Lines+1);
	    System.out.println("---------------------------Analysis End---------------------------");
	}
	
	public  void UseJS(List<SootClass> classesChain) { //Analyze whether the app use JavaScript
		
		//outer:
		 for (SootClass sc : classesChain) {
			 
				for (SootMethod sm : sc.getMethods()) {
					if(sm.isConcrete()){
					Body body = sm.retrieveActiveBody();
					for (Unit unit : body.getUnits()) {
						    LinesofCode++;
						    Stmt stmt=(Stmt)unit;
						    if(stmt instanceof InvokeStmt&&stmt.containsInvokeExpr()){
						    	if(stmt.getInvokeExpr().getArgCount()>0){
						    		String methodName=stmt.getInvokeExpr().getMethod().getName();
						    	    if(methodName.equals("setJavaScriptEnabled")){
						    	    	Value value=GetRightOP(unit);
									    if(value.equals(IntConstant.v(1))){
									    	flagEnableJS = true;
									     // break outer;
									    	}
						    	        }
						             }
						         }
						    }
						 
				}
			 
				
			}
		}	
	}
	
	public void AnalyseAllClasses(List<SootClass> classesChain) { //Analyze all classes
		outer:
		try{
			
		for (SootClass sc : classesChain) {// every class
			for (SootMethod sm : sc.getMethods()) {// every method
				if(sm.isConcrete())// if the method contains body
				{
					AnalyzeOneMethod(sc,sm);//  analyze body
					
				}
				
				
			}
			
			
		}}catch(ConcurrentModificationException e){
			break outer;
			
			
		}
		
		
	}
	
	public void AnalyzeOneMethod(SootClass sc, SootMethod sm) {// analyze each method

		Body body=sm.retrieveActiveBody();
		Iterator<Unit> stmtIt = body.getUnits().snapshotIterator();  
		while (stmtIt.hasNext())  
		{   
			 final Unit unit = (Unit) stmtIt.next();  
			 Stmt stmt = (Stmt) unit;  
//		     System.out.println(unit.toString());
			 if (stmt instanceof InvokeStmt) { //If current unit is a invoke statement
				 if((stmt.containsInvokeExpr())&&(stmt.getInvokeExpr().getArgCount()>0)){//Have arguments 
						 String methodName=stmt.getInvokeExpr().getMethod().getName();//Get method name
						 if(methodName.equals("loadUrl")||methodName.equals("loadDataWithBaseURL")||methodName.equals("loadData")){
						     LocalOrRemotePattern(sc,sm,body,unit,methodName);
						     countLocalAndRemotePattern++;
						     System.out.println();
					      }
						 else if(methodName.equals("setAllowFileAccess")||methodName.equals("setAllowFileAccessFromFileURLs")||methodName.equals("setAllowUniversalAccessFromFileURLs")){
							 FileAccessSettings(sc,sm,unit,methodName);
							 System.out.println();
						 }
					     else if(methodName.equals("addJavascriptInterface")||methodName.equals("removeJavascriptInterface")){
					    	 InterfacePattern(sc,sm,body,unit,methodName);
					    	 System.out.println();
					     }
					     else if(methodName.equals("evaluateJavascript")){
					    	 CallbackPattern(sc,sm,body,unit,methodName);
					    	 System.out.println();
					     }
				     }
		    }
		}
	}
	public void LocalOrRemotePattern(SootClass sc,SootMethod sm,Body body,Unit unit,String methodName){//local pattern or remote pattern
		
		Value paraValue=GetRightOP(unit);
		String paraValueString;
		if(paraValue.toString().startsWith("$")){
			 System.out.println("Class:"+sc.getName());
		     System.out.println("Method:"+sm.getName());
		     System.out.println("Unit:"+unit.toString());
			System.out.println("&: go to Find Value String");
			paraValueString=FindValueString(sc,sm,body,unit,paraValue);
		}
		else{
			paraValueString=paraValue.toString();
		}
		
		LocalOrRemoteJS(sc,sm,unit,paraValueString);
	}
	
    public void LocalOrRemoteJS(SootClass sc,SootMethod sm,Unit unit,String valueString){//Local JS or Remote JS
		
    	if(valueString!=null){
    		valueString=valueString.replaceAll("\"","");
//    		System.out.println(valueString.toString());
            if(valueString.contains("file:")||valueString.contains("javascript:")
            	||valueString.contains("data:")||valueString.contains("overlayHtml")
            	||valueString.contains("<script>")||valueString.contains("</script>")
            	||valueString.startsWith("<html>")||valueString.startsWith("</html>")
            	||valueString.startsWith("<head>")||valueString.startsWith("</head>")
            	||valueString.startsWith("<body>")||valueString.startsWith("</body>")){//use the first way
       	         countLocalPattern++;    
       	         flagUseLocalPattern=true;
       	         System.out.println("Local pattern is used here");
	    	     System.out.println("Class:"+sc.getName());
	    	     System.out.println("Method:"+sm.getName());
	    	     System.out.println("Unit:"+unit.toString());
	    	     System.out.println();
            } 
            else if(valueString.contains("http:")||valueString.contains("https:")
            		||valueString.contains("about:")||valueString.contains("redirect_uri")
            		||valueString.contains("baseUrl")||valueString.contains("url")){
       	         countRemotePattern++;    
                 flagUseRemotePattern=true; 
                 System.out.println("Remote pattern is used here");
	    	     System.out.println("Class:"+sc.getName());
	    	     System.out.println("Method:"+sm.getName());
	    	     System.out.println("Unit:"+unit.toString());
	    	     System.out.println();
                 FindWebViewClient(sc,sm,unit);
            } 
    	}
    	else{
            if(flagChangePattern==true){
            	 countLocalPattern++;    
      	         flagUseLocalPattern=true;
      	         System.out.println("Local pattern is used here");
	    	     System.out.println("Class:"+sc.getName());
	    	     System.out.println("Method:"+sm.getName());
	    	     System.out.println("Unit:"+unit.toString());
	    	     flagChangePattern=false;
	    	     System.out.println();
            }else{
            	countRemotePattern++;    
                flagUseRemotePattern=true; 
                System.out.println("Remote pattern is used here");
	    	    System.out.println("Class:"+sc.getName());
	    	    System.out.println("Method:"+sm.getName());
	    	    System.out.println("Unit:"+unit.toString());
	    	    flagChangePattern=true;
	    	    System.out.println();
                FindWebViewClient(sc,sm,unit);
            }
        }
	}
    
    public void FileAccessSettings(SootClass sc,SootMethod sm,Unit unit,String methodName){//file:// vulnerability
    	
//    	(1)setAllowFileAccess(false);(2)setAllowFileAccessFromFileURLs(false);
//    	(3)setAllowUniversalAccessFromFileURLs(false);
//    	(1)/(2) + (3) no file:// vulnerability
    	System.out.println("Class:"+sc.getName());
    	System.out.println("Method:"+sm.getName());
    	System.out.println("Unit:"+unit.toString());
    	Value booleanValue;
    	if(methodName.equals("setAllowFileAccess")){
    		booleanValue=GetRightOP(unit);
		    if(booleanValue.equals(IntConstant.v(0))){
		    	flagSetAllowFileAccess=false;
		    	System.out.println("setAllowFileAccess(false) here");
	        }
    	}
    	else if(methodName.equals("setAllowFileAccessFromFileURLs")){
    		booleanValue=GetRightOP(unit);
		    if(booleanValue.equals(IntConstant.v(0))){
		    	flagSetAllowFileAccess=false;
		    	System.out.println("setAllowFileAccessFromFileURLs(false) here");
	        }
    	}
    	else if(methodName.equals("setAllowUniversalAccessFromFileURLs")){
    		booleanValue=GetRightOP(unit);
		    if(booleanValue.equals(IntConstant.v(0))){
		    	flagSetAllowHttpAccess=false;
		    	System.out.println("setAllowUniversalAccessFromFileURLs(false) here");
	        }
    	}
    }
	
	public void FindWebViewClient(SootClass sc,SootMethod sm,Unit unit){
		
		   Value VbWebview=GetInvoker(unit);
		   System.out.println("Class:"+sc.getName());
  	       System.out.println("Method:"+sm.getName());
  	       System.out.println("Unit:"+unit.toString());
  	       if(VbWebview!=null){
  	    	   System.out.println("The WebView:"+VbWebview.toString());
		   }else{
			   System.out.println("WebViewClass");
		   }
		   if(SearchWebViewClientOfoneWV(sc,sm,VbWebview)==true)//?????WebView????????????????????????????????????????????? 
		   {
			   System.out.println("Has a WebViewCLient");
		   } 
		   else{
			   System.out.println("No WebViewCLient");
		   }
	}
	
	public void InterfacePattern(SootClass sc,SootMethod sm,Body body,Unit unit,String methodName){
		
	        if(methodName.equals("addJavascriptInterface")) { //Use the interface pattern
	        	System.out.println("Interface pattern is used here");
		    	System.out.println("Class:"+sc.getName());
		    	System.out.println("Method:"+sm.getName());
		    	System.out.println("Unit:"+unit.toString());
			    countInterfacePattern++;     
			    flagUseInterfacePattern = true;
			    Value interfaceValue=GetSecondRightOP(unit);
			    String interfaceNameString;
			    if(interfaceValue.toString().startsWith("$")){//
			    	interfaceNameString=FindValueString(sc,sm,body,unit,interfaceValue);
			    }
			    else{
			    	interfaceNameString=interfaceValue.toString();
			    }
			    if(interfaceNameString!=null){
			    	System.out.println("Register a JS interface named: "+interfaceNameString); 
			    	if(PatternUsedOnHigherVersion(body,unit)==false){
			    	    countExposedJSInterface++;
			    	    if(!JSInterfaceName.contains(interfaceNameString)){
			    	        JSInterfaceName.add(interfaceNameString);
			    	    }
			    	}
			    	else{
			    		System.out.println("JS interface is registered on android version later than 4.2"); 
			    	}
			    }else{
			    	System.out.println("Actually, no JS interface has been registered.");
			    }
			    System.out.println();
		    }
		    if(methodName.equals("removeJavascriptInterface")){
		    	 System.out.println("removeJavascriptInterface is used here");
		    	 System.out.println("Class:"+sc.getName());
		    	 System.out.println("Method:"+sm.getName());
		    	 System.out.println("Unit:"+unit.toString()); 
		         Value interfaceValue=GetRightOP(unit);
				 String interfaceNameString;
				 if(interfaceValue.toString().startsWith("$")){//
				     interfaceNameString=FindValueString(sc,sm,body,unit,interfaceValue);
				 }
				 else{
				     interfaceNameString=interfaceValue.toString();
				 }
                 if(interfaceNameString!=null){
                	 System.out.println("JS interface named "+interfaceNameString+" is removed.");
                	 if(!RemovedJSInterfaceName.contains(interfaceNameString)){
                		  RemovedJSInterfaceName.add(interfaceNameString);
                	 }
                 }else{
 			    	 System.out.println("Actually, no JS interface has been removed.");
 			    }	
                System.out.println();
		    }
	}
	
	private boolean PatternUsedOnHigherVersion(Body body,Unit addJSUnit){
		//If JS interface is registered on Android versions later than 4.2,the vulnerability no longer exists
		
		boolean flagHigherVersionOnly=false;
		Chain<Unit> unitChains=body.getUnits();
		Unit succUnit=addJSUnit;
		Unit curUnit;
		while(succUnit!=unitChains.getFirst()){
		   curUnit=unitChains.getPredOf(succUnit);
		   Stmt curStmt=(Stmt) curUnit;
		   if(curStmt instanceof IfStmt){
			   Value IfValue=((IfStmt) curStmt).getCondition();
			   Stmt targetStmt=((IfStmt) curStmt).getTarget();
			   Unit targetUnit=targetStmt;
			   if(IfValue.toString().contains("<")&&IsSuccUnit(targetUnit,addJSUnit,unitChains)==true){
				   System.out.println("If stmt:"+curStmt);
				   System.out.println("target unit is succ of addjs unit");
				   List<ValueBox> vbList=IfValue.getUseBoxes();
				   if(vbList.size()>=2){
					   if(vbList.get(1)==null){
						   continue;
					   }
					   int version=Integer.parseInt(vbList.get(1).getValue().toString());
					   System.out.println("version:"+version);
					   if(version>=17){
						   Value versionValue=vbList.get(0).getValue();
						   System.out.println("version value:"+versionValue);
						   Unit predUnit=unitChains.getPredOf(curUnit);
						   Stmt predStmt=(Stmt) predUnit;
						   System.out.println("predStmt:"+predStmt.toString());
						   if(predStmt instanceof AssignStmt){
							   Value leftValue=((AssignStmt)predStmt).getLeftOpBox().getValue();
							   Value rightValue=((AssignStmt)predStmt).getRightOpBox().getValue();
							   System.out.println(leftValue);
							   System.out.println(rightValue);
							   if(leftValue.equals(versionValue)&&rightValue.toString().equals("<android.os.Build$VERSION: int SDK_INT>")){
								   flagHigherVersionOnly=true;
							       break;
							   }
						   }
						   curUnit=predUnit;
					   }
				   }
			   }
		   }
		   succUnit=curUnit;
		}
		return flagHigherVersionOnly;
	}
	
	public void CallbackPattern(SootClass sc,SootMethod sm,Body body,Unit unit,String methodName){
		
		 if(methodName.equals("evaluateJavascript")) { //use the callback pattern
	    	   System.out.println("Callback pattern is used here");
	    	   System.out.println("Class:"+sc.getName());
	    	   System.out.println("Method:"+sm.getName());
	    	   System.out.println("Unit:"+unit.toString());
	    	   System.out.println();
		       countCallbackPattern++;
		       flagUseCallbackPattern=true;
	      }
	}
	
	public boolean SearchWebViewClientOfoneWV(SootClass sc, SootMethod sm,Value WebViewValue) {// For each WebView, find its WebViewClient
		
		boolean flagWVCInCurrentMethod = false;
		boolean flagWVCInCurrentClass = false;
		boolean flagWVCAsParameter = false;
		flagWVCInCurrentMethod = SearchWebViewClientInCurrentMethod(sc,sm,WebViewValue);
		if(flagWVCInCurrentMethod==true){
			 System.out.println("Find WebViewClient in current method.");
			 return true;
		}
		else{
			flagWVCInCurrentClass = SearchWebViewClientInCurrentClass(sc);
			if(flagWVCInCurrentClass==true){
				System.out.println("Find WebViewClient in current class.");
				return true;
			}
			else{
				flagWVCAsParameter = SearchWebViewAsParameter(sc,sm,WebViewValue);
				if (flagWVCAsParameter == true) {
					 System.out.println("Find WebViewClient as a parameter.");
					 return true;
				} else {
					 SootClass superClass=sc.getSuperclass();
					 System.out.println("Super class:"+superClass.getName());
					 if(superClass.getName().equals("android.webkit.WebViewClient")){
						 System.out.println("The super class is a WebViewClient.");
						 SMcheckWebViewClientNavigation(superClass.getName());
						 return true;
					 }
					 else{
						 return false;
					 }
				}
			}
		}
	}

	public boolean SearchWebViewClientInCurrentMethod(SootClass sc,SootMethod sm,Value WebViewValue) {// Find a WebviewClient in current method
		
		System.out.println("------------Search WebViewClient In Current Method---------------");
		boolean flagWebViewClientInCurrentMethod = false;
		Body body = sm.retrieveActiveBody();
		for (Unit unit : body.getUnits()) {
			Stmt curStmt=(Stmt) unit;
			if(curStmt instanceof InvokeStmt){
				if(curStmt.containsInvokeExpr()&&curStmt.getInvokeExpr().getArgCount()>0){//has arguments
					String methodName=curStmt.getInvokeExpr().getMethod().getName();//Get method name
					Value leftValue=GetInvoker(unit);
					if(methodName.equals("setWebViewClient")&&leftValue.equals(WebViewValue)){
						System.out.println(leftValue.toString()+":setWebViewClient");
						Value rightValue=GetRightOP(unit);
						String WVCString;
						if (rightValue.toString().startsWith("$")) {// ????????
							System.out.println("WebViewClient:"+rightValue.toString());
							WVCString=FindValueString(sc,sm,body,unit,rightValue);
//							wVCString = SearchStringInOneBody(body, GetRightOP(unit),0);
						} else {
							WVCString=rightValue.toString();
						}
						if(WVCString!=null){
							flagWebViewClientInCurrentMethod = true;
							System.out.println("Class:"+sc.getName());
							System.out.println("Method:"+sm.getName());
							System.out.println("Unit:"+unit.toString());
							int index = WVCString.indexOf(" ", 0);
							String ClassName = WVCString.substring(index + 1);
							System.out.println("WebViewClient class name:"+ClassName);
							SMcheckWebViewClientNavigation(ClassName);
						}else{
							System.out.println("???????--------");
						}
						break;
					}
				}
			}
		}
		return flagWebViewClientInCurrentMethod;
	}
	
	public boolean SearchWebViewClientInCurrentClass(SootClass sc) {// ????????????WebViewClient?????

		System.out.println("------------Search WebViewClient In Current Class---------------");
		boolean flagWebViewClientInCurrentClass = false;
		for (SootMethod sm : sc.getMethods()) {
			if (sm.isConcrete()) {
				Body body = sm.retrieveActiveBody();
				for (Unit unit : body.getUnits()) {
					Stmt curStmt=(Stmt) unit;
					if(curStmt instanceof InvokeStmt){
						if(curStmt.containsInvokeExpr()&&curStmt.getInvokeExpr().getArgCount()>0){//has arguments
							String methodName=curStmt.getInvokeExpr().getMethod().getName();//Get method name
							if(methodName.equals("setWebViewClient")){
//								flagWebViewClientInCurrentClass = true;
								System.out.println("setWebViewClient");
								Value rightValue=GetRightOP(unit);// ?WebViewClient???
								String WVCString;
								if (rightValue.toString().startsWith("$")) {// ????????
									System.out.println("WebViewClient:"+rightValue.toString());
									WVCString=FindValueString(sc,sm,body,unit,rightValue);
//									wVCString = SearchStringInOneBody(body, GetRightOP(unit),0);
								} else {
									WVCString=rightValue.toString();
								}
								if (WVCString == null) {
									
								} else {
									System.out.println("WebViewClient String:"+WVCString);
									flagWebViewClientInCurrentClass = true;
									System.out.println("Class:"+sc.getName());
									System.out.println("Method:"+sm.getName());
									System.out.println("Unit:"+unit.toString());
//									String ClassDefine = VbWVC.toString();
									int index = WVCString.indexOf(" ", 0);
									String ClassName =WVCString.substring(index + 1);
									SMcheckWebViewClientNavigation(ClassName);
								}
							}
						}
					}
				}
			}
		}
		return flagWebViewClientInCurrentClass;
	}

	public boolean SearchWebViewAsParameter(SootClass sc,SootMethod sm, Value VbWebview) {// 

		System.out.println("------------Search WebView As Parameter---------------");
		boolean flagWVCAsParameter = false;
		Body body = sm.retrieveActiveBody();
		for (Unit unit : body.getUnits()) { 
			if(unit instanceof IdentityStmt){
				if (GetLeftOP(unit).equals(VbWebview)) {
					String ValueName = GetRightOP(unit).toString();// ??????????????????WebView????
					int index = ValueName.indexOf(" ");
					String WVClassName = ValueName.substring(index + 1);
					flagWVCAsParameter = SMSearchWebViewClientInWebViewCLass(WVClassName);
					break;
				}
			} 
			else if(unit instanceof AssignStmt){// ?????????????
				if (GetLeftOP(unit).equals(VbWebview)) {
					
					Value rightValue=GetRightOP(unit);// ?WebViewClient???
					String WVCString;
					if (rightValue.toString().startsWith("$")) {// ????????
						System.out.println(rightValue.toString());
						WVCString=FindValueString(sc,sm,body,unit,rightValue);
//						wVCString = SearchStringInOneBody(body, GetRightOP(unit),0);
					} else {
						WVCString=rightValue.toString();
					}
					
					if(WVCString!=null){
					       int index =WVCString.indexOf(" ");
					       String WVClassName = WVCString.substring(index + 1);
					       flagWVCAsParameter = SMSearchWebViewClientInWebViewCLass(WVClassName);
					}
					else{
						
					}
				break;
				}
			} 
			else if(unit instanceof InvokeStmt){// ??????????????
				System.out.println(unit.toString());
				if (GetLeftOP(unit)!=null&&GetLeftOP(unit).equals(VbWebview)) {
				}
			}
		}
		return flagWVCAsParameter;
	}

	public boolean SMSearchWebViewClientInWebViewCLass(String WebViewClassName) {// ??WebView?????????WebViewClient????

		System.out.println("------------Search WebViewClient In WebView Class---------------");
		boolean flagWebViewClientInWebViewClass = false;
		for (SootClass sc : classesChain) {
			if (sc.getName().toString().equals(WebViewClassName)) {// ????WebViewClient??????????????
				for (SootMethod sm : sc.getMethods()) {// ????????????
					if (sm.isConcrete()) {
						Body body = sm.retrieveActiveBody();
						for (Unit unit : body.getUnits()) {
							Stmt curStmt=(Stmt) unit;
							if(curStmt instanceof InvokeStmt){
								String methodName=curStmt.getInvokeExpr().getMethod().getName();//Get method name
								if(methodName.equals("setWebViewClient")){
									flagWebViewClientInWebViewClass= true;
									Value rightValue=GetRightOP(unit);// ?WebViewClient???
									String WVCString;
									if (rightValue.toString().startsWith("$")) {// ????????
										System.out.println(rightValue.toString());
										WVCString=FindValueString(sc,sm,body,unit,rightValue);
//										wVCString = SearchStringInOneBody(body, GetRightOP(unit),0);
									} else {
										WVCString=rightValue.toString();
									}
									if(WVCString!=null){
										flagWebViewClientInWebViewClass=true;
										System.out.println("Class:"+sc.getName());
										System.out.println("Method:"+sm.getName());
										System.out.println("Unit:"+unit.toString());
									    int index = WVCString.indexOf(" ", 0);
									    String WVCClassName = WVCString.substring(index + 1);
									    SMcheckWebViewClientNavigation(WVCClassName);
									}
									else{
										System.out.println("This WebView does not have any WebviewClient.");
									}
								}
							}
						}
					}
				}
				break;
			}
		}
//		if (flagWebViewClientInWebViewClass == true) {
//			System.out.println("??????WebView???????WebViewCient");
//		} else {
//			System.out.println("??????WebView??????????WebViewCient");
//		}
		return flagWebViewClientInWebViewClass;
	}

	public boolean SMSearchWebviewclientClass(SootMethod sm, Value ValueName) {// ??????WebViewClient?????????????P????

		System.out.println("------------Search WebViewClient Class---------------");
		boolean flagWVCnavigation = false;
		if (sm.isConcrete()) {
			Body body = sm.retrieveActiveBody();
			for (Unit unit : body.getUnits()) {
				if(unit instanceof AssignStmt)
				{
					if (GetLeftOP(unit).equals(ValueName)) {// ????????????WebviewClient??????????????
						String ClassDefine = GetRightOP(unit).toString();
						int index = ClassDefine.indexOf(" ", 0);
						String ClassName = ClassDefine.substring(index + 1);
						SMcheckWebViewClientNavigation(ClassName);
					}
				}
			}
		}
		return flagWVCnavigation;
	}

	public void SMcheckWebViewClientNavigation(String ClassName) { // ?????????WebviewClient??????????class??,?????Class????????shouldOverrideURLLoading????????????WebView???????????????
		boolean flagoverrideMethod=false; //???????shouldovverrideUrlLoading????
		if(ClassName.equals("android.webkit.WebViewClient")){
			flagWebViewNavigation=true;
			System.out.println("Default WebViewClient!");
			return;
		}
		for (SootClass sc : classesChain) {
			if (sc.getName().equals(ClassName)) {// ????WebViewClient??????????????
				for (SootMethod sm : sc.getMethods()) {// ?????????????????overideUrlLoading????
					if ((sm.isConcrete()) && (sm.getName().equals("shouldOverrideUrlLoading"))) {
						flagoverrideMethod=true;
						System.out.println("???shouldOverrideUrlLoading????");
						Body b = sm.retrieveActiveBody();
						for (Unit unit : b.getUnits()) {
							if(unit instanceof ReturnStmt){// ??return???
								if (GetReturnValue(unit).equals(IntConstant.v(0))) {
									System.out.println("return false");
									flagWebViewNavigation = true;
								}
								if (GetReturnValue(unit).toString().contains("$")) {// ????????????$?????
									for (Unit ut2 : b.getUnits()) {
										if(ut2 instanceof AssignStmt){// ???????
										{
											if (ut2.toString().contains("shouldOverrideUrlLoading")) {// return
												System.out.println("super.shouldOverrideUrlLoading()???");
												flagWebViewNavigation= true;
											} else {
												if (GetLeftOP(ut2).equals(GetReturnValue(unit))) {
													if (GetRightOP(ut2).equals(IntConstant.v(0))) {// ????????WebView?????
														System.out.println("????????WebView?????");
														flagWebViewNavigation = true;
													}
												}
											}
										}
									}
								}
							}
						}
					    if(unit instanceof InvokeStmt){
					    	 if(unit.toString().contains("loadUrl(")||unit.toString().contains("loadData(")||unit.toString().contains("loadDataWithBaseURL(")){
					    		 System.out.println("??????loadUrl???");
					    		 flagWebViewNavigation = true;
					    	 }
					    }
					    if(unit instanceof IfStmt){
					    	if(unit.toString().contains("URI.parse(url).getHost().equals(")||unit.toString().contains(").equals(URI.parse(url).getHost)")||unit.toString().contains("URI.parse(paramString).getHost().equals(")||unit.toString().contains(").equals(URI.parse(paramString).getHost)")){
					    		trust=true;
					    		System.out.println("Class:"+sc.getName());
					    	     System.out.println("Method:"+sm.getName());
					    	     System.out.println("Unit:"+unit.toString());
					    	     System.out.println("????????????????????????????");
					    	     System.out.println();
					    		
					    	}
					    	

					    }
					}
					break; //break when find the shouldoveerideUrlLoading
				}
			}
			break;//break when find the webviewclient class
		  }
		}
		if(flagoverrideMethod == false){//not override method
			flagUseRemotePattern=true;
			countRemotePattern++;
//			flagSecondRisk=true;
			countWVhasNavigation++;
			System.out.println("???WebViewClient??"+ClassName+"???????shouldOverrideUrlLoading()???????????????????");
		}
		else{
			if (flagWebViewNavigation == true) {
			    flagUseRemotePattern=true;
				countRemotePattern++;
//				flagSecondRisk=true;
				countWVhasNavigation++;
			    System.out.println("???WebViewClient??"+ClassName+"????shouldOverrideUrlLoading()????,?????????????????????????????");
		     } 
			else {
				flagUseRemotePattern=true;
				countRemotePattern++;
			    System.out.println("???WebViewClient??"+ClassName+"????shouldOverrideUrlLoading()??????????????????????");
		    }
		}
	}

	public boolean FoMsearchJSInterfaceClassInCurrentMethod(SootMethod sm,Value valueName,Value JsInterfaceName) {// search Js interface
		
		boolean flagFindIt = false;
		Body body = sm.retrieveActiveBody();
		boolean FindAssign=false;
		for (Unit unit: body.getUnits()) {
			if(unit instanceof AssignStmt){  // is an assignment statement
				if (GetLeftOP(unit).equals(valueName)) {
					FindAssign=true;
					Value JSInterfaceValue;
					if(GetRightOP(unit)!=null){
						if(GetRightOP(unit).toString().startsWith("new")){//new 
							JSInterfaceValue=GetRightOP(unit);
					    }
					    else if(!(GetRightOP(unit).toString().equals(GetLastRightOP(unit)))){//
					    	JSInterfaceValue=GetLastRightOP(unit);
					   }
					   else{
						   JSInterfaceValue=SearchStringInOneBody(body,GetRightOP(unit),0);
					    }
					  if(JSInterfaceValue!=null){
						flagFindIt = true;//???
						String ClassDefine = JSInterfaceValue.toString();
					    int index1 = ClassDefine.indexOf(" ", 0);
					    int index2 = ClassDefine.lastIndexOf(" ");
					    String ClassName = "";
					    if (index1 != index2) {
					     	ClassName = ClassDefine.substring(index1 + 1, index2);
					    } else {
					     	ClassName = ClassDefine.substring(index1 + 1);
					    }
				    	if (ClassName.equals("java.lang.Object")) {
				    		System.out.println("Js interface is an object 1");
//				    		flagThirdMethodaddTag = false;
				    		if(!JSInterfaceName.contains(JsInterfaceName)){
				    			System.out.println("????JsInterfaceName??????"+JsInterfaceName.toString());
							    JSInterfaceName.add(JsInterfaceName.toString());
				    		}
							System.out.println("???????????@???");
					    }
						else{//????????????????????
							 System.out.println("JSInterface????"+ClassName);
							 FMcheckJSclassAnnotation(ClassName,JsInterfaceName);
						}
					}
					break;
				  }
				}
			}
		}
		if(FindAssign==false){
			for(Unit unit2:body.getUnits()){
				if(unit2 instanceof IdentityStmt){//@?????????
					if (GetLeftOP(unit2).equals(valueName)) {
						String ValueName = GetRightOP(unit2).toString();// ??????????????????Js class ????
						int index = ValueName.indexOf(" ");
						String ClassName = ValueName.substring(index + 1);
						if (ClassName.equals("java.lang.Object")) { //java.lang.Object??????????????????????
							System.out.println("js interaface is an object 2");
//							flagThirdMethodaddTag = false;
							if(!JSInterfaceName.contains(JsInterfaceName)){
							     System.out.println("????JsInterfaceName??????"+JsInterfaceName.toString());
							     JSInterfaceName.add(JsInterfaceName.toString());
							}
							System.out.println("???????????@???");
					    }
						else{//????????????????????
							 System.out.println("JSInterface????:"+ClassName);
							 FMcheckJSclassAnnotation(ClassName,JsInterfaceName);
						}
						break;
					}
				}
			}
		}
		return flagFindIt;
	}

	public void SearchValueInSourceMethod(SootMethod sm,int depth){//?????????????????????????????????
		String InvokeStmtContains=sm.getName();
		CallGraph callGraph = Scene.v().getCallGraph();
		Iterator<MethodOrMethodContext> sources = new Sources(callGraph.edgesInto(sm));
		while(sources.hasNext()){
			SootMethod sourceMethod = (SootMethod)sources.next();
			Body body=sourceMethod.retrieveActiveBody();
			for(Unit unit:body.getUnits()){
				if(unit.toString().contains(InvokeStmtContains)){
					if(depth<7){
				         SearchValueInSourceMethod(sourceMethod,++depth);
					}
				}
			}
		}
	}
	
	public boolean FMcheckJSclassAnnotation(String classname,Value JsInterfaceName) {// ?????????JS?????????????class??,?????Class?????????????????@???
		boolean addTag = false;// ???JS?????Class???????@??????????
		System.out.println("????@???,"+"????:"+classname);
		for (SootClass sc : classesChain) {
			if (sc.getName().equals(classname)) {// ???JSInterface??
				System.out.println("??classChain?????????");
				for (SootMethod sm : sc.getMethods()) {
					List<Tag> tags = sm.getTags();
					for (Tag tag : tags) {
						System.out.println("Tag?????"+tag.getClass().toString());
						if (tag.getClass().getName().equals("soot.tagkit.VisibilityAnnotationTag")) {
							// ???????????@JavaScriptInterface?????????????????????????????????????????????????
							System.out.println("????"+sm.getName()+"??????@???");
							addTag = true;
							break;
						}
					}
					if(addTag==true){//add annotation
						break;
					}
				}
				break;// ??????????????
			}
		}
		if (addTag == false) {
//			flagThirdMethodaddTag = false;
			if(!JSInterfaceName.contains(JsInterfaceName)){
			   System.out.println("????JsInterfaceName??????"+JsInterfaceName.toString());
			   JSInterfaceName.add(JsInterfaceName.toString());
			   System.out.println("???????????@???");
			}
		} else {
			System.out.println("?????????@???");
		}
		return addTag;
	}
    
	public void AnalyzeFileVulner(){//Analyze the file:// vulnerability
		if((flagSetAllowFileAccess==false)&&(flagSetAllowHttpAccess==false)){
			flagPotentialFileVulner=false;
		}
		else{
			flagPotentialFileVulner=true;
		}
	}
	
	public void AnalyzeUXSSVulner(){
		if(flagWebViewNavigation==true){
			flagPotentialUXSSVulner=true;
		}
		else{
			flagPotentialUXSSVulner=false;
		}
	}
	
    public void AnalyzeJSInterfaceVulner(){ // Analyze the JS interface vulnerability according to the two list
    	
    	String TempJSInterfacename;
    	for(int i=0;i<RemovedJSInterfaceName.size();i++){
    		TempJSInterfacename=RemovedJSInterfaceName.get(i);
    		if(JSInterfaceName.contains(TempJSInterfacename)){
    			JSInterfaceName.remove(TempJSInterfacename);
    		}
    	}
    	if(JSInterfaceName.size()!=0){
    		flagPotentialInterfaceVulner=true;
    		countExposedJSInterface=JSInterfaceName.size();
    	}
    	else{
    		flagExposedNoJSInterface=true;
    	}
    }

	public void PrintResult() {//Print results
		
		System.out.println("----------------------------Print results----------------------------");
		if (flagEnableJS == true) {
			System.out.println("The app enables JavaScript.");
			if (flagUseLocalPattern == true) {
				System.out.print("Local pattern is used ");
				System.out.println(countLocalPattern+" times.");
				AnalyzeFileVulner();  //Analyze file:// vulnerability
//				if (flagFileVulner==true){
//					System.out.println("file:// vulnerability.");
//				} else {
//					System.out.println("No file:// vulnerability.");
//				}
			}
			if (flagUseRemotePattern == true) {
				System.out.print("Remote pattern is used ");
				System.out.println(countRemotePattern+" times.");
				AnalyzeUXSSVulner();  //Analyze uxss vulnerability
//				if (flagUXSSVulner == true) {
//					System.out.println("WebView UXSS vulnerability");
//				} else {
//					System.out.println("No WebView UXSS vulnerability");
//				}
			}
			if (flagUseInterfacePattern== true) {
				System.out.print("Interface pattern is used ");
				System.out.println(countInterfacePattern+" times.");
				AnalyzeJSInterfaceVulner();//analyze two lists
//				if (flagInterfaceVulner== true) {
//					System.out.println("The app exsits the JS??interface vulnerability.");
//					System.out.println("The app exposes "+countExposedJSInterface+" JS interfaces.");
//		    		for(int i=0;i<JSInterfaceName.size();i++){
//		    			System.out.println("Name:"+JSInterfaceName.get(i));
//		        	}
//				} else {
//					System.out.println("NO JS??interface vulnerability.");
//				}
			}
			if (flagUseCallbackPattern == true){
				System.out.print("Callback pattern is used ");
				System.out.println(countCallbackPattern+" times.");
			}
			System.out.println("Lines of code:"+LinesofCode);
			System.out.println("sum:"+countLocalAndRemotePattern);
		} else {
			System.out.println("The app does not enable JavaScript.");
		}
	}
}
