/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import java.io.IOException;
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

/**
 *
 * @author Developer
 */
public class OpentimestampsModule implements DataSourceIngestModule {
    
    public OpentimestampsModule() {
        int number;
    }
    
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        int number = 1;
        return ProcessResult.OK;
    }

//    @Override
//    public void shutDown() {
//        int number = 1;
//    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
       int number = 1;
    }
   
}
