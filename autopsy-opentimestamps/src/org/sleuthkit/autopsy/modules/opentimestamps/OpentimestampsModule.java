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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.eternitywall.ots.OtsRaw;
/**
 *
 * @author Developer
 */
public class OpentimestampsModule implements DataSourceIngestModule {
    
    private static final IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private static final String moduleName = OpentimestampsModuleFactory.getModuleName();
    private final String fileInCaseDatabase = "/WINDOWS/system32/ntmsapi.dll"; // Probably  
    private IngestJobContext context;
    private String outputDirPath;
    private String derivedFileInCaseDatabase;
    
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
        if (refCounter.get(context.getJobId()) == 1) {
            try{
                //my code here
                // There will be two tasks: data source analysis and import of 
                // the results of the analysis.
                progressBar.switchToDeterminate(1);
                
                if(dataSource instanceof Image){
                    Image image = (Image) dataSource;
                    String dataSourcePath = image.getPaths()[0];
                    //Maybe do some debug logging here
                    //OtsRaw.
                }
                else{
                    return ProcessResult.OK;
                }
                
                return ProcessResult.OK;
            } catch (Exception ex) {
                Logger logger = IngestServices.getInstance().getLogger(moduleName);
                logger.log(Level.SEVERE, "Failed to perform analysis", ex);  //NON-NLS
                return ProcessResult.ERROR;
            }
        }
        
        return ProcessResult.OK;
    }

//    @Override
//    public void shutDown() {
//        int number = 1;
//    }

//    @Override
//    public void startUp(IngestJobContext context) throws IngestModuleException {
//       int number = 1;
//    }
   
}
