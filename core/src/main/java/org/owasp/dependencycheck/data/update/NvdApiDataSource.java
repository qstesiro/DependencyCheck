/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.NvdApiException;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
import java.io.File;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public class NvdApiDataSource implements CachedWebDataSource {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdApiDataSource.class);
    /**
     * The thread pool size to use for CPU-intense tasks.
     */
    private static final int PROCESSING_THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    /**
     * The configured settings.
     */
    private Settings settings;
    /**
     * Reference to the DAO.
     */
    private CveDB cveDb = null;
    /**
     * The properties obtained from the database.
     */
    private DatabaseProperties dbProperties = null;

    @Override
    public boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        this.cveDb = engine.getDatabase();
        if (isUpdateConfiguredFalse()) {
            return false;
        }
        dbProperties = cveDb.getDatabaseProperties();

        ZonedDateTime lastModifiedRequest = dbProperties.getTimestamp(DatabaseProperties.NVD_API_LAST_MODIFIED);
        NvdCveClientBuilder builder = NvdCveClientBuilder.aNvdCveApi();
        if (lastModifiedRequest != null) {
            ZonedDateTime end = lastModifiedRequest.minusDays(-120);
            builder.withLastModifiedFilter(lastModifiedRequest, end);
        }
        String key = settings.getString(Settings.KEYS.NVD_API_KEY);
        if (key != null) {
            builder.withApiKey(key)
                    .withDelay(3000)
                    .withThreadCount(4);
        }
        ExecutorService processingExecutorService = null;
        try {
            processingExecutorService = Executors.newFixedThreadPool(PROCESSING_THREAD_POOL_SIZE);
            List<Future<NvdApiProcessor>> submitted = new ArrayList<>();
            int errorCount = 0;
            try (NvdCveClient api = builder.build()) {
                while (api.hasNext()) {
                    try {
                        Collection<DefCveItem> items = api.next();
                        if (items != null && !items.isEmpty()) {
                            Future<NvdApiProcessor> f = processingExecutorService.submit(new NvdApiProcessor(cveDb, items));
                            submitted.add(f);
                            errorCount = 0;
                        }
                    } catch (NvdApiException ex) {
                        if (ex.getCause() instanceof JsonProcessingException) {
                            errorCount += 1;
                            if (errorCount > 10) {
                                throw ex;
                            }
                        } else {
                            throw ex;
                        }
                    }
                }
                lastModifiedRequest = api.getLastUpdated();
            } catch (Exception e) {
                throw new UpdateException("Error updating the NVD Data", e);
            }

            try {
                for (Future f : submitted) {
                    LOGGER.error("updating");
                    while (!f.isDone()) {
                        Thread.sleep(500);
                    }
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new UpdateException(ex);
            }
            dbProperties.save(DatabaseProperties.NVD_API_LAST_MODIFIED, lastModifiedRequest);
            return true;
        } finally {
            if (processingExecutorService != null) {
                processingExecutorService.shutdownNow();
            }
        }
    }

    /**
     * Checks if the system is configured NOT to update.
     *
     * @return false if the system is configured to perform an update; otherwise
     * true
     */
    private boolean isUpdateConfiguredFalse() {
        if (!settings.getBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, true)) {
            return true;
        }
        boolean autoUpdate = true;
        try {
            autoUpdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Invalid setting for auto-update; using true.");
        }
        return !autoUpdate;
    }

    @Override
    public boolean purge(Engine engine) {
        boolean result = true;
        try {
            final File dataDir = engine.getSettings().getDataDirectory();
            final File db = new File(dataDir, engine.getSettings().getString(Settings.KEYS.DB_FILE_NAME, "odc.mv.db"));
            if (db.exists()) {
                if (db.delete()) {
                    LOGGER.info("Database file purged; local copy of the NVD has been removed");
                } else {
                    LOGGER.error("Unable to delete '{}'; please delete the file manually", db.getAbsolutePath());
                    result = false;
                }
            } else {
                LOGGER.info("Unable to purge database; the database file does not exist: {}", db.getAbsolutePath());
                result = false;
            }
            final File traceFile = new File(dataDir, "odc.trace.db");
            if (traceFile.exists() && !traceFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", traceFile.getAbsolutePath());
                result = false;
            }
            final File lockFile = new File(dataDir, "odc.update.lock");
            if (lockFile.exists() && !lockFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", lockFile.getAbsolutePath());
                result = false;
            }
        } catch (IOException ex) {
            final String msg = "Unable to delete the database";
            LOGGER.error(msg, ex);
            result = false;
        }
        return result;
    }

}
