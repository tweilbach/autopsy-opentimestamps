/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

import java.util.List;

/**
 *
 * @author Developer
 */
public class OpentimestampsReport {
    
    public boolean success;
    public String infoResult;
    public List<String> messages;

    public OpentimestampsReport() {
        this.success = false;
    }

//    public OpentimestampsInfo(String infoResult) {
//        this.infoResult = infoResult;
//        this.success = true;
//    }

//    public boolean isKnown() {
//        return validStamp;
//    }
//
    public String getInfoResult() {
        return infoResult;
    }
}
