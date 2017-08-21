/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.opentimestamps;

/**
 *
 * @author Developer
 */

import com.eternitywall.ots.DetachedTimestampFile;
import com.eternitywall.ots.Hash;
import com.eternitywall.ots.OpenTimestamps;
//import com.eternitywall.ots.OtsCli;
import com.eternitywall.ots.Timestamp;
import com.eternitywall.ots.Utils;
import com.eternitywall.ots.op.OpSHA256;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.IngestServices;

public class OpentimestampsFunctions {
    
    private static final String moduleName = OpentimestampsModuleFactory.getModuleName();
    Logger logger = IngestServices.getInstance().getLogger(moduleName);
    
    private static HashMap<String,String> readSignature(String file) throws Exception {
        Path path = Paths.get(file);
        if(!path.toFile().exists()){
            throw new Exception();
        }
        Properties properties = new Properties();
        properties.load(new FileInputStream(file));
        HashMap<String,String> privateUrls = new HashMap<>();
        for(String key : properties.stringPropertyNames()) {
            String value = properties.getProperty(key);
            privateUrls.put(key,value);
        }
        return privateUrls;
    }
    
    public static String info (String filePath) {
        try {
            Path pathOts = Paths.get(filePath);
            byte[] byteOts = Files.readAllBytes(pathOts);
            DetachedTimestampFile detached = DetachedTimestampFile.deserialize(byteOts);
            String infoResult = OpenTimestamps.info(detached);
//            System.out.println(infoResult);
            return infoResult;
        } catch (IOException e) {
//            log.severe("No valid file");
            return "No valid file";
        }
    }
    
    public static List<String> multistamp(List<String> argsFiles, List<String> calendarsUrl, Integer m, String signatureFile, String algorithm){
        //Create return message object
        List<String> messages = new ArrayList<>();
        // Parse input privateUrls
        HashMap<String, String> privateUrls = new HashMap<>();
        if(signatureFile != null && signatureFile != "") {
            try {
                privateUrls = readSignature(signatureFile);
            } catch (Exception e) {
                //log.severe("No valid signature file");
                messages.add("No valid signature file");
            }
        }

        // Make list of detached files
        HashMap<String, DetachedTimestampFile> mapFiles = new HashMap<>();
        for (String argsFile : argsFiles){
            try {
                File file = new File(argsFile);
                Hash hash = Hash.from( file, Hash.getOp(algorithm)._TAG());
                mapFiles.put( argsFile, DetachedTimestampFile.from(hash) );
            } catch (IOException e) {
                messages.add(e.getMessage());
                //log.severe("File read error");
                messages.add("File read error");
                return messages;
            } catch (NoSuchAlgorithmException e) {
                messages.add(e.getMessage());
                //log.severe("Crypto error");
                messages.add("Crypto error");
                return messages;
            }
        }

        // Stamping
        Timestamp stampResult;
        try {
            List<DetachedTimestampFile> detaches = new ArrayList(mapFiles.values());
            stampResult = OpenTimestamps.stamp(detaches, calendarsUrl, m, privateUrls);
            if(stampResult == null){
               throw new IOException();
            }
        } catch (IOException e) {
            messages.add(e.getMessage());
            messages.add("Stamp error");
            //log.severe("Stamp error");
            return messages;
        }

        // Generate ots output files
        for (Map.Entry<String, DetachedTimestampFile> entry : mapFiles.entrySet()){

            String argsFile = entry.getKey();
            DetachedTimestampFile detached = entry.getValue();
            String argsOts = argsFile + ".ots";
            try {
                Path path = Paths.get(argsOts);
                if (Files.exists(path)) {
                    //System.out.println("File '" + argsOts + "' already exist");
                    messages.add("File '" + argsOts + "' already exist");
                } else {
                    Files.write(path, detached.serialize());
                    //System.out.println("The timestamp proof '" + argsOts + "' has been created!");
                    messages.add("The timestamp proof '" + argsOts + "' has been created!");
                }
            }catch (Exception e){
                messages.add(e.getMessage());
                messages.add("File '" + argsOts + "' writing error");
                //log.severe("File '" + argsOts + "' writing error");
            }
        }
        return messages;
    }
    
    private static String stamp(Hash hash, List<String> calendarsUrl, Integer m, String signatureFile) {
        HashMap<String, String> privateUrls = new HashMap<>();
        byte[] shasum = null;
        if (signatureFile != null && signatureFile != "") {
            try {
                privateUrls = readSignature(signatureFile);
            } catch (Exception e) {
                //log.severe("No valid signature file");
                return "No valid signature file";
            }
        }

        String argsOts = Utils.bytesToHex(shasum) + ".ots";
        Path path = Paths.get(argsOts);
        if(path.toFile().exists()) {
            //System.out.println("File '" + argsOts + "' already exist");
            return "File '" + argsOts + "' already exist";
        }

        try {
            DetachedTimestampFile detached = DetachedTimestampFile.from(hash);
            Timestamp stampResult = OpenTimestamps.stamp(detached, calendarsUrl, m, privateUrls);
            Files.write(path, stampResult.serialize());
            //System.out.println("The timestamp proof '" + argsOts + "' has been created!");
            return "The timestamp proof '" + argsOts + "' has been created!";
        } catch (Exception e) {
            //log.severe("Invalid shasum");
            return "Invalid shasum";
        }
    }
    
    public static String verify (String argsOts) {
        //FileInputStream fis = null;
        try {

            Path pathOts = Paths.get(argsOts);
            byte[] byteOts = Files.readAllBytes(pathOts);
            DetachedTimestampFile detachedOts = DetachedTimestampFile.deserialize(byteOts);
            Long timestamp = null;
            byte[] shasum = null;

//            if (shasum == null){
                // Read from file
            String argsFile = argsOts.replace(".ots","");
            File file = new File(argsFile);
            //System.out.println("Assuming target filename is '" + argsFile + "'");
            DetachedTimestampFile detached = DetachedTimestampFile.from(new OpSHA256(), file);
            timestamp = OpenTimestamps.verify(detachedOts,detached);
//            } else {
//                // Read from hash option
//                //System.out.println("Assuming target hash is '" + Utils.bytesToHex(hash.getValue()) + "'");
//                DetachedTimestampFile detached = DetachedTimestampFile.from(hash);
//                timestamp = OpenTimestamps.verify(detachedOts,detached);
//            }

            if(timestamp == null){
                //System.out.println("Pending or Bad attestation");
                return "Pending or Bad attestation";
            }else {
                //System.out.println("Success! Bitcoin attests data existed as of "+ new Date(timestamp*1000) );
                return "Success! Bitcoin attests data existed as of " + new Date(timestamp*1000);
            }

        } catch (Exception e) {
            //log.severe("No valid file");
            return "No valid file" + e;
//        } finally {
//            try {
//                fis.close();
//            }catch  (IOException e) {
//                //log.severe("No valid file");
//                return "No valid file";
//            }
        }
    }

    public static String upgrade (String argsOts, boolean shrink) {
        try {
            Path pathOts = Paths.get(argsOts);
            byte[] byteOts = Files.readAllBytes(pathOts);
            DetachedTimestampFile detachedOts = DetachedTimestampFile.deserialize(byteOts);

            boolean changed = OpenTimestamps.upgrade(detachedOts);
            if(shrink == true) {
                detachedOts.getTimestamp().shrink();
            }

            if(!shrink && !changed) {
                return "Timestamp not upgraded";
            } else {
                // Copy Bak File
                byte[] byteBak = Files.readAllBytes(pathOts);
                Path pathBak = Paths.get(argsOts+".bak");
                Files.write(pathBak, byteBak);

                // Write new Upgrade Result
                Files.write(pathOts, detachedOts.serialize());
                
                return "Timestamp successfully upgraded";
            }

        } catch (IOException e) {
            return "No valid file";
        } catch (Exception e) {
            //e.printStackTrace();
            return "Shrink error";
        }
    }
}
