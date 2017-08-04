/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 *
 * @author Developer
 */
public class OpentimestampsModuleFactory {
    
    private static final String VERSION_NUMBER = "0.0.1";

    public String getModuleDisplayName() {
        return NbBundle.getMessage(OpentimestampsModuleFactory.class, "OpentimestampsModuleFactory.moduleName");

    }

    @Override
    public String getModuleDescription() {
        return getModuleDisplayName();
    }

    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER;
    }

    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        return new OpentimestampsGlobalSettingsPanel();
    }
    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new OpentimestampsSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings) {
        return new OpentimestampsJobSettingsPanel((OpentimestampsSettings) settings);
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
//        throw new UnsupportedOperationException();
        return new OpentimestampsModule();
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return false;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
//        String apiKey = ((VirusTotalOnlineCheckSettings) settings).getApiKey();
//        if(apiKey == null) { 
//            apiKey = "";
//        }
//        return new VirusTotalOnlineCheckModule(apiKey);
        throw new UnsupportedOperationException();
    }
}
