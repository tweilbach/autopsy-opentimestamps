/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Semaphore;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.HashUtility;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.coreutils.ErrorInfo;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.externalresults.ExternalResults;
import org.sleuthkit.autopsy.externalresults.ExternalResultsImporter;
import org.sleuthkit.autopsy.externalresults.ExternalResultsXMLParser;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProcessTerminator;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestModuleReferenceCounter;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.Tag;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import java.io.FileWriter;
import java.util.Date;

import com.eternitywall.ots.OtsFunctions;
import java.nio.file.Paths;
import org.sleuthkit.autopsy.casemodule.services.Blackboard;
import org.sleuthkit.datamodel.AbstractFile;
/**
 *
 * @author Developer
 */
public class OpentimestampsModule implements DataSourceIngestModule {
    
    private TagsManager tagsManager;
    private String tagNameString = "Opentimestamps";
    private TagName moduleTag;
    
    private static final IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private static final String moduleName = OpentimestampsModuleFactory.getModuleName();
    private final String fileInCaseDatabase = "/WINDOWS/system32/ntmsapi.dll"; // Probably  
    private IngestJobContext context;
    private String outputDirPath;
    private String derivedFileInCaseDatabase;
    private List<String> calendarURLs = new ArrayList<>();
    private String algorithm = "SHA256";
    private String signatureFile = "";
    
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
        if (refCounter.incrementAndGet(context.getJobId()) == 1) {
            // Create an output directory for this job.
            outputDirPath = Case.getCurrentCase().getModuleDirectory() + File.separator + moduleName; //NON-NLS
            File outputDir = new File(outputDirPath);
            if (outputDir.exists() == false) {
                outputDir.mkdirs();
            }
        }
    }
    
//    public OpentimestampsModule() {
//        int number;
//    }
    
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        
        Logger logger = IngestServices.getInstance().getLogger(moduleName);
        List<String> Messages = new ArrayList<>();
        OpentimestampsReport otsReport = new OpentimestampsReport();
        
        //Blackboard currentBlackboard = Case.getCurrentCase().getServices().getBlackboard();
        
        if (refCounter.get(context.getJobId()) == 1) {
            try{
                //my code here
                // There will be two tasks: data source analysis and import of 
                // the results of the analysis.
                progressBar.switchToDeterminate(1);
                
                stamp(dataSource, otsReport);
                
                return ProcessResult.OK;
            } catch (Exception ex) {
                //Logger logger = IngestServices.getInstance().getLogger(moduleName);
                logger.log(Level.SEVERE, "Failed to perform analysis", ex);  //NON-NLS
                return ProcessResult.ERROR;
            }
        }
        
        return ProcessResult.OK;
    }
    
    public void stamp(Content dataSource, OpentimestampsReport otsReport){
        
        Logger logger = IngestServices.getInstance().getLogger(moduleName);
        
        if(dataSource instanceof Image){
            Image image = (Image) dataSource;
            String dataSourcePath = image.getPaths()[0];
            List<String> dsFilePath = new ArrayList<>();
            dsFilePath.add(dataSourcePath);
            //Maybe do some debug logging here
            logger.log(Level.INFO, dataSourcePath);
            //
            otsReport.messages = OtsFunctions.multistamp(dsFilePath, calendarURLs, calendarURLs.size(), null, algorithm);
 
            for (String message : otsReport.messages){
                logger.log(Level.INFO, message);
            }

            otsReport.success = true;

        }
        else if(dataSource instanceof File){

            otsReport.success = false;
            otsReport.messages.add("Data source format not supported");
            //return ProcessResult.OK;
        }
        
        createOtsReport(otsReport,dataSource.getName());
       
    }
    
//    public otsResult upgrade(Content datasource){
//        otsResult res = new otsResult();
//        
//        res.success = true;
//        
//        return res;
//    }
//    
//    public otsResult info(Content datasource){
//        otsResult res = new otsResult();
//        
//        res.success = true;
//        
//        return res;
//    }
//    
//    public otsResult verify(Content datasource){
//        otsResult res = new otsResult();
//        
//        res.success = true;
//        
//        return res;
//    }

    
    private void createOtsTag(AbstractFile file, OpentimestampsReport otsInfo) throws TskCoreException {
        tagsManager.addContentTag(file, moduleTag, "OTS Info: " + otsInfo.getInfoResult());
    }
    
    private void addOtsReport(String reportName){
        try{
            Case.getCurrentCase().addReport(outputDirPath, moduleName, reportName);
        }catch(TskCoreException ex){
            
        }
    }
    
    private void createOtsReport(OpentimestampsReport otsReport, String reportName){
        try{
            
            FileWriter writer = new FileWriter(Paths.get(outputDirPath, reportName + "_OTS_Proof_Report.txt").toString());
            
            for(String line: otsReport.messages) {
              writer.write(line);
            }
            
            writer.close();
            
            addOtsReport(reportName);
            
        } catch(IOException e){
            
        }

    }
    
    private void appendOtsReport(){
        
    }
    
    private class otsResult{
        
        boolean success;
        List<String> messages;
        
        public otsResult(){
            success = false;
        }
    }
   
}
