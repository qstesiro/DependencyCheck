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
package org.owasp.dependencycheck.data.update.nvd.api;

import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import java.util.Collection;
import java.util.concurrent.Callable;
import org.owasp.dependencycheck.data.nvd.ecosystem.CveEcosystemMapper;
import org.owasp.dependencycheck.data.nvdcve.CveDB;

/**
 * Stores a collection of NVD CVE Data from the NVD API into the database.
 *
 * @author Jeremy Long
 */
public class NvdApiProcessor implements Callable<NvdApiProcessor> {

    private final CveDB cveDB;
    private final Collection<DefCveItem> data;
    private final CveEcosystemMapper mapper = new CveEcosystemMapper();

    public NvdApiProcessor(final CveDB cveDB, Collection<DefCveItem> data) {
        this.cveDB = cveDB;
        this.data = data;
    }

    @Override
    public NvdApiProcessor call() throws Exception {
        for (DefCveItem entry : data) {
            cveDB.updateVulnerability(entry, mapper.getEcosystem(entry));
        }
        return this;
    }

}
