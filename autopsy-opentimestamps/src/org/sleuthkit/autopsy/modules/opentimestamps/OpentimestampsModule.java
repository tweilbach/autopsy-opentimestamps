/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import org.sleuthkit.datamodel.TskCoreException;
import java.io.File;
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
import org.sleuthkit.autopsy.casemodule.services.FileManager;

import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.sleuthkit.datamodel.AbstractFile;
/**
 *
 * @author Developer
 */
public class OpentimestampsModule implements DataSourceIngestModule {
    
    //private TagsManager tagsManager;
    //private String tagNameString = "Opentimestamps";
   // private TagName moduleTag;
    
    private static final IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private static final String moduleName = OpentimestampsModuleFactory.getModuleName();
    //private final String fileInCaseDatabase = "/WINDOWS/system32/ntmsapi.dll"; // Probably  
    private IngestJobContext context;
    private String outputDirPath;
    //private String derivedFileInCaseDatabase;
    
    private String algorithm = "SHA256";
    private String signatureFile = "";
    private String btcConfPath = "";
    private List<String> calendarURLs = new ArrayList<>();
    
    Logger logger = IngestServices.getInstance().getLogger(moduleName);
    
    public OpentimestampsModule (List<String> calendarUrls, String btcConf){
        try{
            if(calendarUrls != null){
                calendarURLs = calendarUrls;
            }
            if(!"".equals(btcConf) && btcConf != null){
                btcConfPath = btcConf;
            }
            
        } catch(Exception ex){
            logger.log(Level.INFO, "Error reading Opentimestamps custom settings: {0}", ex);
        }
    }
    
    //Execution flow and setup
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
            progressBar.switchToDeterminate(2);
            
            
            progressBar.progress(1);
            
            //Collection  that will hold the datasourcepath of the indivudual file paths depending on the datasource type
            List<String> dataSourcePaths = getDataSourcePaths(dataSource);
            
            //logging
            //for (String path : dataSourcePaths){
            //    logger.log(Level.INFO, "This is the path: "+ path);
            //}
            //Check if there is more than 1 to process.
            if(dataSourcePaths.size() == 1){
                logger.log(Level.INFO, "About to get path");
                String dataSourcePath = dataSourcePaths.get(0);
                logger.log(Level.INFO, "About to get Process");
                otsProcess(dataSourcePath, dataSource);

            } else if (dataSourcePaths.size() > 1){
                logger.log(Level.INFO, "We have more than one path");
                for (String path : dataSourcePaths){
                    otsProcess(path, dataSource);
                }
            }
            
            progressBar.progress(2);

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
            logger.log(Level.INFO, "OTS process - No proof exists so we'll create the first proof ");
            createOtsProof(dataSourcePath, dataSource.getName());
            logger.log(Level.INFO, "OTS process - Getting onfo on the proof we just created. ");
            infoOtsProof(dataSourcePath, dataSource.getName());
        }
    }
    
    
    //OTS functions
    public void createOtsProof(String dataSourcePath, String dataSourceName){
        
        List<String> otsMessages = new ArrayList<>();
        //Logger logger = IngestServices.getInstance().getLogger(moduleName);
        
        //Maybe do some debug logging here
        //logger.log(Level.INFO, dataSourcePath);
        //Adding the string back into a list since mutistamp takes a list as input - dirty I know
         List<String> dsFilePaths = new ArrayList<>();
         dsFilePaths.add(dataSourcePath);
        
        //logger.log(Level.INFO, "About to stamp file: " + dataSourcePath);
        //for (String url: calendarURLs){
        //    logger.log(Level.INFO, "Using Calendar server: " + url);
        //}
        String stampResult = OpentimestampsFunctions.multistamp(dsFilePaths, null, 0, null, algorithm);
        //logger.log(Level.INFO, stampResult);
        
        otsMessages.add(stampResult);
        //logger.log(Level.INFO, "createOtsProof - Creating report.");
        createOtsReport(otsMessages,dataSourceName);
       
    }
    
    private String infoOtsProof(String path, String reportName){
        
        List<String> otsMessages = new ArrayList<>();
        
        String infoResult = OpentimestampsFunctions.info(getOtsProofPath(path));
        
        otsMessages.add(infoResult);
            
        createOtsReport(otsMessages, reportName);
        
        return infoResult;
    }
    
    private void upgradeOtsProof(String path, String reportName){
        try{
            
            List<String> otsMessages = new ArrayList<>();
            
            String upgradeResult = OpentimestampsFunctions.upgrade(getOtsProofPath(path), true);
            
            otsMessages.add(upgradeResult);
            
            logger.log(Level.INFO, upgradeResult);
            
            createOtsReport(otsMessages, reportName);
            
        } catch (Exception ex){
            logger.log(Level.WARNING, "Failed to upgrade proof. Assuming it is not yet upgraded.", ex);
        }
    }
    
    private void verifyOtsProof(String path, String reportName){
        try{
            List<String> otsMessages = new ArrayList<>();
            logger.log(Level.INFO, getOtsProofPath(path));
            //Second parameter to verify is null since we won't ever be seding the hash - we should have a reference to the original file
            String verifyResult = OpentimestampsFunctions.verify(getOtsProofPath(path));
            
            logger.log(Level.INFO, verifyResult);
            
            otsMessages.add(verifyResult);
            
            String stampInfo = OpentimestampsFunctions.info(getOtsProofPath(path));
                    
            otsMessages.add("Timestamp details: " + stampInfo);
            
            createOtsReport(otsMessages, reportName);
            
        }catch (Exception ex){
            logger.log(Level.WARNING, "Failed to valdate proof.", ex);
        }
    }
    
    
    //Reporting functions
    private void addOtsReport(String reportName){
        try{
            Case.getCurrentCase().addReport(outputDirPath, moduleName, reportName);
        }catch(TskCoreException ex){
            logger.log(Level.SEVERE, "Failed to add Opentimestamps report", ex);
        }
    }
    
    private void createOtsReport(List<String> otsMessages, String reportName){
        try{
            
            String reportPath = Paths.get(outputDirPath, reportName + "_OTS_Report.txt").toString();
            
            logger.log(Level.INFO, "About to writer report, path is: " + reportPath);
            
            boolean appendMode = appendReport(reportPath);
            
            //ReportWriter reportWriter = appendMode(reportPath);
            try(FileWriter fileWriter = new FileWriter(reportPath, appendMode)){
            
                logger.log(Level.INFO, "This is the darn file writer: " + fileWriter);
                //logger.log(Level.INFO, "ANd this is its state: " + reportWriter.exists.toString());

                for(String line: otsMessages) {

                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                    LocalDateTime now = LocalDateTime.now();

                    String formattedDate = dtf.format(now);
                    fileWriter.write(formattedDate + ": " + line);

                    logger.log(Level.INFO, "Added line to report: {0}: {1}", new Object[]{formattedDate, line});

                    fileWriter.write(System.lineSeparator());
                }
            }
            
            if(!appendMode){
                addOtsReport(reportName);
                logger.log(Level.INFO, "Added report to Case: " + reportName);
            }
            
        } catch(Exception ex){
            logger.log(Level.SEVERE, "Failed to create Opentimestamps report", ex);
        }

    }
    
    
    //Helper functions
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
        } else {
            //Some logging
            logger.log(Level.INFO, dataSource.getName());
            logger.log(Level.INFO, dataSource.getUniquePath());
            logger.log(Level.INFO, dataSource.toString());
            logger.log(Level.INFO, "Datasource is not an image file - multiple file paths to process");
            FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
            //finding ALL files "%"
            List<AbstractFile> files = fileManager.findFiles(dataSource, "%");
            for (AbstractFile file: files){
                //Check if it is a file since we cant't stamp a directory
                if(file.isFile()){
                    dsFilePaths.add(file.getLocalAbsPath());
                    logger.log(Level.INFO, "Found file in logical file set - this is the path: "+ file.getLocalAbsPath());
                }
            }
        }
        
        return dsFilePaths;
    }
    
    private boolean appendReport(String reportPath){
         File f = new File(reportPath);
         
        if(f.exists() && !f.isDirectory()) { 
            return true;
        }
        else if(!f.exists()){
            return false;
        }
        
        return false;
    }
    
}
