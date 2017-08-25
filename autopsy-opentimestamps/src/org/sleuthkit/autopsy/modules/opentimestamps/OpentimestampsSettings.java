/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import java.util.ArrayList;
import java.util.Arrays;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
/**
 *
 * @author Developer
 */
public class OpentimestampsSettings implements IngestModuleIngestJobSettings {
    
    private ArrayList<String> calendarUrls;
    private String calendarString = "";
    private String btcConfPath = "";
    private static final long serialVersionUID = 1L;

    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }
    
    public void setBtcConfPath(String path){
        this.btcConfPath = path;
    }
    
    public String getBtcConfPath(){
        return btcConfPath;
    }
    
    public void setCalendarString(String urls){
        calendarString = urls;
    }
    
    public String getCalendarString(){
        return calendarString;
    }
    
    public ArrayList<String> getcalendarUrls(){
        calendarUrls = new ArrayList<>(Arrays.asList(calendarString.split("\\s*,\\s*")));
        
        return calendarUrls;
    }
}
