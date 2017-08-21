/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import org.sleuthkit.datamodel.TskCoreException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestModuleReferenceCounter;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import java.io.FileWriter;
import java.util.Date;

import com.eternitywall.ots.OtsFunctions;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.sleuthkit.autopsy.modules.opentimestamps.OpentimestampsFunctions;
/**
 *
 * @author Developer
 */
public class OpentimestampsModule implements DataSourceIngestModule {
    
    //private TagsManager tagsManager;
    private String tagNameString = "Opentimestamps";
   // private TagName moduleTag;
    
    private static final IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private static final String moduleName = OpentimestampsModuleFactory.getModuleName();
    //private final String fileInCaseDatabase = "/WINDOWS/system32/ntmsapi.dll"; // Probably  
    private IngestJobContext context;
    private String outputDirPath;
    //private String derivedFileInCaseDatabase;
    private List<String> calendarURLs = new ArrayList<>();
    private String algorithm = "SHA256";
    private String signatureFile = "";
    Logger logger = IngestServices.getInstance().getLogger(moduleName);
    
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
    
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        
        //if (refCounter.get(context.getJobId()) == 1) {
            try{
                //my code here
                // There will be two tasks: data source analysis and import of 
                // the results of the analysis.
                progressBar.switchToDeterminate(1);
                //Get all the paths for data source
                List<String> dataSourcePaths = getDataSourcePaths(dataSource);
                
                //logging
                for (String path : dataSourcePaths){
                    logger.log(Level.INFO, "This is the path: "+ path);
                }
                //Check if there is more than 1 to process.
                if(dataSourcePaths.size() == 1){
                    logger.log(Level.INFO, "About to get path");
                    String dataSourcePath = dataSourcePaths.get(0);
                    logger.log(Level.INFO, "About to get Process");
                    otsProcess(dataSourcePath, dataSource);
                    
                } else if (dataSourcePaths.size() > 1){
                    logger.log(Level.INFO, "We have more tahn one path");
                    for (String path : dataSourcePaths){
                        otsProcess(path, dataSource);
                    }
                }
                
                return ProcessResult.OK;
            } catch (Exception ex) {
                //Logger logger = IngestServices.getInstance().getLogger(moduleName);
                logger.log(Level.SEVERE, "Failed to perform analysis", ex);  //NON-NLS
                return ProcessResult.ERROR;
            }
        //}
        
        //return ProcessResult.OK;
    }

    private void otsProcess(String dataSourcePath, Content dataSource) {
        if (checkOtsProofExists(dataSourcePath)){
            logger.log(Level.INFO, "OTS process - Proof exists so we will attmept to upgarde it");
            upgradeOtsProof(dataSourcePath, dataSource.getName());
            logger.log(Level.INFO, "OTS process - It was upgraded so we'll just move along and verify it");
            verifyOtsProof(dataSourcePath, dataSource.getName());
            logger.log(Level.INFO, "OTS process - Upgrade returned false so we did not verify ");
        }
        else {
            logger.log(Level.INFO, "OTS process - No proof exists so we'll create the firts proof ");
            stamp(dataSourcePath, dataSource.getName());
            logger.log(Level.INFO, "OTS process - Getting onfo on the proof we just created. ");
            infoOtsProof(dataSourcePath, dataSource.getName());
        }
    }
    
    public void stamp(String dataSourcePath, String dataSourceName){
        
        //Logger logger = IngestServices.getInstance().getLogger(moduleName);
        List<String> otsMessages;
        
        //Maybe do some debug logging here
        logger.log(Level.INFO, dataSourcePath);
        //Adding the string back into a list since mutistamp takes a list as input - dirty I know
         List<String> dsFilePaths = new ArrayList<>();
         dsFilePaths.add(dataSourcePath);
        //
        otsMessages = OtsFunctions.multistamp(dsFilePaths, calendarURLs, calendarURLs.size(), null, algorithm);

//            for (String message : otsReport.messages){
//                logger.log(Level.INFO, message);
//            }
        
        createOtsReport(otsMessages,dataSourceName);
       
    }
    
    private void addOtsReport(String reportName){
        try{
            Case.getCurrentCase().addReport(outputDirPath, moduleName, reportName);
        }catch(TskCoreException ex){
            logger.log(Level.SEVERE, "Failed to add Opentimestamps report", ex);
        }
    }
    
    private void createOtsReport(List<String> otsMessages, String reportName){
        try{
            
            String reportPath = Paths.get(outputDirPath, reportName + "_OTS_Proof_Report.txt").toString();
            
            try (FileWriter writer = appendMode(reportPath)) {
                for(String line: otsMessages) {
                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                    LocalDateTime now = LocalDateTime.now();
                    
                    String formattedDate = dtf.format(now);
                    writer.write(formattedDate + ": " + line);
                    writer.append(System.lineSeparator());
                }
            }
            
            addOtsReport(reportName);
            
        } catch(IOException ex){
            logger.log(Level.SEVERE, "Failed to create Opentimestamps report", ex);
        }

    }
    
    private FileWriter appendMode(String reportPath) throws IOException{
        File f = new File(reportPath);
        
        //If report already exists
        if(f.exists() && !f.isDirectory()) { 
            try{
                return new FileWriter(reportPath,true);
            }
            catch(IOException ex){
                logger.log(Level.WARNING, "Failed to determine Opentimestamsp report state", ex);
            }
        }
        else {
            try{
                return new FileWriter(reportPath);
            }
            catch(IOException ex){
                logger.log(Level.WARNING, "Failed to determine Opentimestamsp report state", ex);
            }
        }
        
        return new FileWriter(reportPath,true);
    }
    
    private boolean checkOtsProofExists(String dataSourcePath){
        try{
            File f = new File(getOtsProofPath(dataSourcePath));
            logger.log(Level.INFO, "Checking if {0} exists.", f.getPath());
            if(f.exists() && f.isFile()) { 
                logger.log(Level.INFO, "{0} does exist.", f.getPath());
                return true;
            }
        }catch(Exception ex){
            logger.log(Level.WARNING, "Failed to verify if Opentimestamps proof exists", ex);
        }
        
        return false;
    }
    
    private void upgradeOtsProof(String path, String reportName){
        try{
            
            List<String> otsMessages = new ArrayList<>();
            
            String upgradeResult = com.eternitywall.ots.OtsFunctions.upgrade(getOtsProofPath(path), true);
            
            otsMessages.add(upgradeResult);
            
            logger.log(Level.INFO, upgradeResult);
            
            createOtsReport(otsMessages, reportName);
            
//            if (upgradeResult.toLowerCase().contains("timestamp not upgraded") && upgradeResult.toLowerCase().contains("timestamp is not complete")){
//                return false;
//            }
//            else if (upgradeResult.toLowerCase().contains("timestamp is not complete") && !upgradeResult.toLowerCase().contains("timestamp is not complete")){
//                return true;
//            }
//            else if (upgradeResult.toLowerCase().contains("timestamp has been successfully upgraded")){
//                return true;
//            }
        } catch (Exception ex){
            logger.log(Level.WARNING, "Failed to upgrade proof. Assuming it is not yet upgraded.", ex);
        }
    }
    
    private void verifyOtsProof(String path, String reportName){
        try{
            List<String> otsMessages = new ArrayList<>();
            logger.log(Level.INFO, getOtsProofPath(path));
            //Second parameter to verify is null since we won't ever be seding the hash - we should have a reference to the original file
            String verifyResult = com.eternitywall.ots.OtsFunctions.verify(getOtsProofPath(path));
            
            
            logger.log(Level.INFO, verifyResult);
            
            otsMessages.add(verifyResult);
            
            createOtsReport(otsMessages, reportName);
            
        }catch (Exception ex){
            logger.log(Level.WARNING, "Failed to valdate proof.", ex);
        }
    }
    
    private String infoOtsProof(String path, String reportName){
        
        List<String> otsMessages = new ArrayList<>();
        
        String infoResult = com.eternitywall.ots.OtsFunctions.info(getOtsProofPath(path));
        
        otsMessages.add(infoResult);
            
        createOtsReport(otsMessages, reportName);
        
        return infoResult;
    }
    
    private String getOtsProofPath(String dataSourcePath){
        return dataSourcePath + ".ots";
    }
    
    private List<String> getDataSourcePaths(Content dataSource) throws TskCoreException{
        List<String> dsFilePaths = new ArrayList<>();
        
        if(dataSource instanceof Image){
            Image image = (Image) dataSource;
            String dataSourcePath = image.getPaths()[0];
            dsFilePaths.add(dataSourcePath);
            //Some logging
            logger.log(Level.INFO, dataSource.getName());
            logger.log(Level.INFO, dataSource.getUniquePath());
            logger.log(Level.INFO, dataSource.toString());
        } else if(dataSource instanceof File){
            File file = (File) dataSource;
            String dataSourcePath = file.getPath();
            dsFilePaths.add(dataSourcePath);
            //Some logging
            logger.log(Level.INFO, dataSource.getName());
            logger.log(Level.INFO, dataSource.getUniquePath());
            logger.log(Level.INFO, dataSource.toString());
        } else {
            //Some logging
            logger.log(Level.INFO, dataSource.getName());
            logger.log(Level.INFO, dataSource.getUniquePath());
            logger.log(Level.INFO, dataSource.toString());
        }
        
        return dsFilePaths;
    }
   
}
