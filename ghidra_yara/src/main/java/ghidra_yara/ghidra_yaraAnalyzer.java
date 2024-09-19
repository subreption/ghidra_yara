/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_yara;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.program.model.listing.CodeUnit;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;

// YARA for Java imports (embedded variant)
import com.github.subreption.yara.embedded.*;

import generic.jar.ResourceFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.File;

import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompilationCallback.ErrorLevel;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraMeta;
import com.github.subreption.yara.YaraRule;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraScanner;
import com.github.subreption.yara.YaraString;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_yaraAnalyzer extends AbstractAnalyzer
{
	private static final String NAME = "YARA Analyzer";
	private static final String DESCRIPTION =
		"Leverage the YARA library to perform signature matching";
	
	private static final String BOOKMARK_CATEGORY = "YARA";

	protected static final String SCAN_METHOD_OPTION_NAME = "Scanning method";
	protected static final String SCAN_METHOD_OPTION_DESCRIPTION =
		"Scanning method: monolithic or block-by-block.";
	protected static final ScanMethod SCAN_METHOD_OPTION_DEFAULT_VALUE = ScanMethod.MONOLITHIC;

	protected ScanMethod scanMethod = SCAN_METHOD_OPTION_DEFAULT_VALUE;
	
	protected static final String LOAD_BUILTIN_OPTION_NAME = "Load built-in rules shipped with the analyzer";
	protected static final String LOAD_BUILTIN_OPTION_DESCRIPTION =
		"The rules and rulesets included with the analyzer will be loaded first.";
	protected Boolean loadBuiltinRules = true;
	
	protected static final String CREATE_DATATYPES_OPTION_NAME = "Attempt to create data types for matches";
	protected static final String CREATE_DATATYPES_OPTION_DESCRIPTION =
		"Upon match, the analyzer will attempt to create data types (ex. arrays) for the matched data.";
	protected Boolean createDatatypes = true;
	
	protected static final String ADD_BOOKMARKS_OPTION_NAME = "Add bookmarks for matches";
	protected static final String ADD_BOOKMARKS_OPTION_DESCRIPTION =
		"Upon match, the analyzer will add a bookmark to the exact location of the match in the program.";
	protected Boolean addBookmarks = true;
	
	protected static final String EXT_YARA_RULES_PATH_OPTION_NAME = "Path to external rules directory";
	protected static final String EXT_YARA_RULES_PATH_OPTION_DESCRIPTION =
		"Path to directory containing rules or rulesets";
	protected File externalRulesPath = getExternalRulesPath();
	
	private YaraImpl yara;
	
	private BookmarkManager bookmarkManager = null;

	public ghidra_yaraAnalyzer()
	{
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}


	@Override
	public boolean canAnalyze(Program program) {
		try {
			if (this.yara == null) {
				this.yara = new YaraImpl();  
				this.yara.close();
			}
		} catch (Exception e) {
			Msg.error(this, "Failed to initialize libyara", e);
			return false;
		} finally {
			this.yara = null;
		}

		bookmarkManager = program.getBookmarkManager();
		
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program)
	{
		options.registerOption(SCAN_METHOD_OPTION_NAME, scanMethod, null,
				SCAN_METHOD_OPTION_DESCRIPTION);
		
		options.registerOption(LOAD_BUILTIN_OPTION_NAME, loadBuiltinRules, null,
				LOAD_BUILTIN_OPTION_DESCRIPTION);
		
		options.registerOption(CREATE_DATATYPES_OPTION_NAME, createDatatypes, null,
				CREATE_DATATYPES_OPTION_DESCRIPTION);
		
		options.registerOption(ADD_BOOKMARKS_OPTION_NAME, createDatatypes, null,
				ADD_BOOKMARKS_OPTION_DESCRIPTION);
		
		options.registerOption(EXT_YARA_RULES_PATH_OPTION_NAME, OptionType.FILE_TYPE,
				null, null, EXT_YARA_RULES_PATH_OPTION_DESCRIPTION);
	}
	
	@Override
	public void optionsChanged(Options options, Program program)
	{
		scanMethod = options.getEnum(SCAN_METHOD_OPTION_NAME, scanMethod);
		loadBuiltinRules = options.getBoolean(LOAD_BUILTIN_OPTION_NAME, loadBuiltinRules);
		createDatatypes = options.getBoolean(CREATE_DATATYPES_OPTION_NAME, createDatatypes);
		addBookmarks = options.getBoolean(ADD_BOOKMARKS_OPTION_NAME, addBookmarks);
		externalRulesPath = options.getFile(EXT_YARA_RULES_PATH_OPTION_NAME, externalRulesPath);
	}
	
	private File getExternalRulesPath() {
		String rpathEnv = System.getenv("YARA_RULES");
		
		if (rpathEnv != null && !rpathEnv.isBlank() && !rpathEnv.isEmpty())
		{
			Path rpath = Path.of(rpathEnv);
			
			if (!Files.isDirectory(rpath, LinkOption.NOFOLLOW_LINKS)) {
				Msg.error(this, String.format(""));
				return null;
			}
			
			return rpath.toFile();
		}
		
		return null;
	}
	
	// Coalesce all program bytes for a monolithic search
	private byte[] getProgramBytes(Program program, MessageLog log)
	{
        Memory memory = program.getMemory();
        long totalSize = memory.getSize();

        byte[] allBytes = new byte[(int) totalSize];
        int offset = 0;

        for (MemoryBlock block : memory.getBlocks())
        {
            if (block.isInitialized())
            {
                try {
                    Address start = block.getStart();
                    int blockSize = (int) block.getSize();

                    // Read the bytes from the memory block
                    byte[] blockBytes = new byte[blockSize];
                    memory.getBytes(start, blockBytes);
                    
                    Msg.info(this, String.format("Coalescing bytes from MemoryBlock %s at %x (%s), size %d.",
                    		block.getName(),
                    		start.getAddressableWordOffset(),
                    		start.getPhysicalAddress().toString(),
                    		blockSize));

                    // Copy the block's bytes into the allBytes array
                    System.arraycopy(blockBytes, 0, allBytes, offset, blockSize);
                    offset += blockSize;

                } catch (MemoryAccessException e) {
                	log.appendException(e);
                }
            }
        }

        return allBytes;
    }
	
	private void handleMatch(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, YaraRule rule, Address baseAddress)
	{
		String metaDescription = "";
		SymbolTable symTable = program.getSymbolTable();
		Listing progListing = program.getListing();
		
		if (monitor.isCancelled())
    	{
    		Msg.info(this, "cancelled!");
    		return;
    	}
		
		// We need to extract the metadata for the match first
		for (YaraMeta curMeta : IterableHelper.toIterable(rule.getMetadata()))
		{
			if (curMeta == null)
				continue;
			
			if (curMeta.getIdentifier().equals("description"))
			{
				String desc = curMeta.getString();
				
				if (!desc.isBlank() && !desc.isEmpty()) {
					metaDescription = desc;
				}
			}
		}
				
	    for (YaraString yaraString : IterableHelper.toIterable(rule.getStrings()))
	    {
	        for (YaraMatch curMatch : IterableHelper.toIterable(yaraString.getMatches()))
	        {
	        	Address matchAddress = baseAddress.add(curMatch.getOffset());
	            
	            String idStr = String.format("YARA_%s_%s", rule.getIdentifier(), matchAddress.getPhysicalAddress().toString());
	            
	            Msg.info(this, String.format("Match: Labeling %s (identifier %s, offset %x, phys address %s, %d bytes)", 
		                idStr, rule.getIdentifier(), curMatch.getOffset(),
		                matchAddress.getPhysicalAddress().toString(),
		                curMatch.getValue().length()));
	            
	            try {
	            	symTable.createLabel(matchAddress, idStr, SourceType.ANALYSIS);
	            	progListing.setComment(matchAddress, CodeUnit.EOL_COMMENT, rule.getIdentifier());
					
					if (createDatatypes)
					{
						byte[] matchBytes = curMatch.getBytes();
						
						// Try to create an array
						ArrayDataType dt = new ArrayDataType(new ByteDataType(),  matchBytes.length, 1);
						try {
							dt.setName(idStr);
						} catch (InvalidNameException e) {
							Msg.error(this, "Failed to name datatype: " + idStr, e);
						}
						
						try {
							progListing.createData(matchAddress, dt);
						} catch (CodeUnitInsertionException e) {
							// Avoid overwriting existent datatypes
							Msg.warn(this, String.format("Could not apply datatype for %s at %s", idStr,
									matchAddress.getPhysicalAddress().toString()), e);
						}
						
					}
					
					// Create bookmarks in the YARA category if enabled
					if (addBookmarks) {
						bookmarkManager.setBookmark(matchAddress, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY, metaDescription);
					}
				} catch (InvalidInputException e) {
					log.appendException(e);
					continue;
				}
	        }
	    }
	}
	
	private void addRuleFile(File file, YaraCompiler compiler) {
		if (file.getName().endsWith(".yar") || file.getName().endsWith(".yara"))
        {
            try {
                Msg.info(this, "Adding rules from " + file.getName());
                
                compiler.addRulesFile(file.toPath().toAbsolutePath().toString(), file.getName(), null);
                
                Msg.info(this, "Loaded YARA rules from file: " + file.getName());
                
            } catch (YaraException e) {
                Msg.error(this, "Error loading YARA rules from file (" + file.getAbsolutePath() + "): " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
	}
	
	private void addRuleFilesRecursive(ResourceFile directory, YaraCompiler compiler)
	{
	    if (directory.isDirectory())
	    {
	        ResourceFile[] files = directory.listFiles();
	        
	        for (ResourceFile file : files)
	        {
	            if (file.isDirectory())
	            {
	            	addRuleFilesRecursive(file, compiler);
	            } else {
	            	addRuleFile(file.getFile(true), compiler);
	            }
	        }
	    }
	}
	
	private void addRuleExtFilesRecursive(File directory, YaraCompiler compiler)
	{
	    if (directory.isDirectory())
	    {
	        File[] files = directory.listFiles();
	        	        
	        for (File file : files)
	        {
	            if (file.isDirectory())
	            {
	            	addRuleExtFilesRecursive(file, compiler);
	            } else {
	            	addRuleFile(file, compiler);
	            }
	        }
	    }
	}
	
	private Boolean addRules(YaraCompiler compiler, MessageLog log)
	{
		Boolean success = false;
				
		Msg.info(this, "Loading YARA rules...");
		
		try {
			// Get the root directory of the "data" folder in your module
            ResourceFile dataDir = Application.getModuleSubDirectory("ghidra_yara", "data/rules");
            
            if (dataDir == null || !dataDir.exists()) {
                Msg.error(this, "Rules data directory not found.");
                return false;
            }
            
            if (loadBuiltinRules)
            	addRuleFilesRecursive(dataDir, compiler);
            
            if (externalRulesPath != null && externalRulesPath.isDirectory() && externalRulesPath.canRead())
            	addRuleExtFilesRecursive(externalRulesPath, compiler);
            
		} catch (IOException e) {
			Msg.warn(this, "Could not find the built-in ruleset file among the resources", e);
			success = false;
		}
		
		
		return success;
	}
	
	private YaraCompilationCallback createCompilationCallback()
	{
	    return (errorLevel, fileName, lineNumber, message) -> {
	    	switch (errorLevel) {
	    	case ErrorLevel.WARNING:
	    		Msg.warn(this, String.format("WARNING: %s (line %d): %s", fileName, lineNumber, message.toString()));
	    		break;
	    	case ErrorLevel.ERROR:
	    		Msg.error(this, String.format("Compiler failed for %s (line %d): %s", fileName, lineNumber, message.toString()));
	    		break;
	    	default:
	    		break;
	    	}
	    };
	}
		
    private void yaraScanMonolithic(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws Exception
    {
    	Address minAddress = program.getMinAddress();
    	
    	byte[] allBytes = getProgramBytes(program, log);
 
        YaraScanCallback scanCallback = v -> {       	
        	handleMatch(program, set, monitor, log, v, minAddress);
        };
        
        try (YaraCompiler compiler = yara.createCompiler())
        {
            compiler.setCallback(createCompilationCallback());
            
            addRules(compiler, log);
            
            try (YaraScanner scanner = compiler.createScanner())
            {
                scanner.setCallback(scanCallback);
                
                Msg.info(this, "Scanning entire program...");
                
                scanner.scan(allBytes);
            } catch (YaraException e)
            {
            	Msg.error(this, "Encountered exception while scanning: " + e.getMessage());
            	
            	throw new RuntimeException(e);
            }
        }
		
		return;
    }
    
    private void yaraScanBlockBased(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws Exception
    {  	
        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler())
        {
            compiler.setCallback(createCompilationCallback());
            
            addRules(compiler, log);
            
            try (YaraScanner scanner = compiler.createScanner())
            {
                Memory memory = program.getMemory();
                
                for (MemoryBlock block : memory.getBlocks())
                {
                    if (block.isInitialized())
                    {
                        try {
                        	Address curBlockAddress = block.getStart();
                            int blockSize = (int) block.getSize();

                            // Read the bytes from the memory block
                            byte[] blockBytes = new byte[blockSize];
                            memory.getBytes(curBlockAddress, blockBytes);
                            
                            Msg.info(this, String.format("Scanning MemoryBlock %s at %x (%s), size %d.",
                            		block.getName(),
                            		curBlockAddress.getAddressableWordOffset(),
                            		curBlockAddress.getPhysicalAddress().toString(),
                            		blockSize));
                            
                            YaraScanCallback scanCallback = v -> {
                            	handleMatch(program, set, monitor, log, v, curBlockAddress);
                            };
                            
                            scanner.setCallback(scanCallback);
                            scanner.scan(blockBytes);
                            
                        } catch (MemoryAccessException e) {
                        	log.appendException(e);
                        }
                    }
                }
            } catch (YaraException e)
            {
            	log.appendException(e);            	
            	throw new RuntimeException(e);
            }
        }
		
		return;
    }
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException
	{
		
		try {
			this.yara = new YaraImpl();
		} catch (Throwable e)
		{
			log.appendException(e);
			return false;
		}
		
		try {
			if (scanMethod.equals(ScanMethod.MONOLITHIC)) {
				yaraScanMonolithic(program, set, monitor, log);
			} else if (scanMethod.equals(ScanMethod.BLOCK_BASED)) {
				yaraScanBlockBased(program, set, monitor, log);
			}
			
			return true;
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
	}
	
	@Override
	public void analysisEnded(Program program)
	{
		// Drop the libyara instance and end the analysis
		try {
			this.yara.close();
		} catch (Exception e) {
			Msg.error(this, "Could not close instance of libyara", e);
		} finally {
			this.yara = null;
		}
		
		super.analysisEnded(program);
	}
}
