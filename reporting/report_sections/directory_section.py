"""
Mixin for directory objects section (users, groups, computers tables).
"""

from datetime import datetime
import json



class DirectorySectionMixin:
    """Mixin for directory objects section (users, groups, computers tables)."""

    def _generate_directory_section(self, users, groups, computers, risks):
        """Generate directory objects section with search and detail views."""
        import json
        from datetime import datetime
        
        def json_serializer(obj):
            """Custom JSON serializer for datetime objects."""
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        def clean_for_json(data):
            """Clean data for JSON serialization."""
            if isinstance(data, dict):
                return {k: clean_for_json(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [clean_for_json(item) for item in data]
            elif isinstance(data, datetime):
                return data.isoformat()
            else:
                return data
        
        # Prepare users data with group memberships
        users_data = []
        for user in users:
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            # Get user risks
            user_risks = [r for r in risks if r.get('affected_object') == user.get('sAMAccountName')]
            
            # Extract group names
            group_names = []
            for group_dn in member_of:
                if 'CN=' in group_dn:
                    try:
                        group_name = group_dn.split('CN=')[1].split(',')[0]
                        group_names.append(group_name)
                    except Exception:
                        pass
            
            # Extract admin group names
            domain_admin_groups = []
            enterprise_admin_groups = []
            schema_admin_groups = []
            for group_dn in member_of:
                group_str = str(group_dn).upper()
                if 'DOMAIN ADMINS' in group_str:
                    try:
                        group_name = group_dn.split('CN=')[1].split(',')[0] if 'CN=' in group_dn else str(group_dn)
                        domain_admin_groups.append(group_name)
                    except Exception:
                        pass
                if 'ENTERPRISE ADMINS' in group_str:
                    try:
                        group_name = group_dn.split('CN=')[1].split(',')[0] if 'CN=' in group_dn else str(group_dn)
                        enterprise_admin_groups.append(group_name)
                    except Exception:
                        pass
                if 'SCHEMA ADMINS' in group_str:
                    try:
                        group_name = group_dn.split('CN=')[1].split(',')[0] if 'CN=' in group_dn else str(group_dn)
                        schema_admin_groups.append(group_name)
                    except Exception:
                        pass
            
            # Format last logon
            last_logon_display = 'N/A'
            days_since_logon = None
            if user.get('lastLogonTimestamp'):
                try:
                    last_logon = user.get('lastLogonTimestamp')
                    if isinstance(last_logon, str):
                        last_logon = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                    if isinstance(last_logon, datetime):
                        last_logon_display = last_logon.strftime('%Y-%m-%d %H:%M:%S')
                        days_since_logon = (datetime.now() - last_logon.replace(tzinfo=None)).days
                except Exception:
                    pass
            
            # Format account age
            account_age_display = 'N/A'
            if user.get('whenCreated'):
                try:
                    when_created = user.get('whenCreated')
                    if isinstance(when_created, str):
                        when_created = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                    if isinstance(when_created, datetime):
                        account_age_days = (datetime.now() - when_created.replace(tzinfo=None)).days
                        account_age_display = f"{account_age_days} days"
                except Exception:
                    pass
            
            # Check SPN
            spns = user.get('servicePrincipalName', []) or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            has_spn = len(spns) > 0
            
            # Check if service account with password never expires
            is_service_account = user.get('isServiceAccount', False)
            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    uac = 0
            password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD flag
            is_service_with_pwd_never_expires = is_service_account and password_never_expires
            
            users_data.append({
                'sAMAccountName': user.get('sAMAccountName', 'N/A'),
                'displayName': user.get('displayName', user.get('sAMAccountName', 'N/A')),
                'groups': group_names,
                'group_count': len(group_names),
                'risk_count': len(user_risks),
                'critical_risks': len([r for r in user_risks if r.get('severity', '').lower() == 'critical']),
                'adminCount': user.get('adminCount', 0),
                'isDisabled': user.get('isDisabled', False),
                'isLocked': user.get('isLocked', False),
                'lastLogon': last_logon_display,
                'daysSinceLastLogon': days_since_logon,
                'accountAge': account_age_display,
                'accountAgeDays': user.get('accountAgeDays'),
                'domainAdminGroups': domain_admin_groups,
                'enterpriseAdminGroups': enterprise_admin_groups,
                'schemaAdminGroups': schema_admin_groups,
                'hasSPN': has_spn,
                'spns': spns,
                'isServiceAccount': is_service_account,
                'isServiceWithPwdNeverExpires': is_service_with_pwd_never_expires,
                'passwordNeverExpires': password_never_expires,
                'createdInLast10Days': user.get('createdInLast10Days', False),
                'createdInLast30Days': user.get('createdInLast30Days', False),
                'createdInLast60Days': user.get('createdInLast60Days', False),
                'createdInLast90Days': user.get('createdInLast90Days', False),
                'groupChangedInLast10Days': user.get('groupChangedInLast10Days', False),
                'groupChangedInLast30Days': user.get('groupChangedInLast30Days', False),
                'groupChangedInLast60Days': user.get('groupChangedInLast60Days', False),
                'groupChangedInLast90Days': user.get('groupChangedInLast90Days', False),
                'adminPrivilegeAgeDays': user.get('adminPrivilegeAgeDays')
            })
        
        # Prepare groups data with members
        groups_data = []
        for group in groups:
            # Try multiple possible member attributes (member is the standard LDAP attribute)
            members = group.get('member', []) or []
            if not members:
                members = group.get('members', []) or []
            if not isinstance(members, list):
                members = [members] if members else []
            
            # Extract member names from DNs
            member_names = []
            for member_dn in members:
                if not member_dn:
                    continue
                # Extract CN from DN
                if 'CN=' in str(member_dn):
                    try:
                        member_name = str(member_dn).split('CN=')[1].split(',')[0]
                        member_names.append(member_name)
                    except Exception:
                        member_names.append(str(member_dn))
                else:
                    member_names.append(str(member_dn))
            
            # Get group risks
            group_risks = [r for r in risks if r.get('affected_object') == group.get('name')]
            
            groups_data.append({
                'name': group.get('name', 'N/A'),
                'member_count': len(member_names),
                'members': member_names,  # All members, not limited
                'risk_count': len(group_risks),
                'critical_risks': len([r for r in group_risks if r.get('severity', '').lower() == 'critical']),
                'is_privileged': any(priv in group.get('name', '').upper() for priv in 
                                    ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'ACCOUNT OPERATORS', 'BACKUP OPERATORS'])
            })
        
        # Prepare computers data
        computers_data = []
        for computer in computers:
            comp_risks = [r for r in risks if r.get('affected_object') == computer.get('name')]
            computers_data.append({
                'name': computer.get('name', 'N/A'),
                'operatingSystem': computer.get('operatingSystem', 'Unknown'),
                'risk_count': len(comp_risks),
                'critical_risks': len([r for r in comp_risks if r.get('severity', '').lower() == 'critical'])
            })
        
        users_rows = self._generate_users_table_rows(users_data, users, risks)
        groups_rows = self._generate_groups_table_rows(groups_data, groups, risks)
        computers_rows = self._generate_computers_table_rows(computers_data, computers, risks)
        dir_page_size = 50
        
        return f"""
        <!-- Directory Objects Section -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-search"></i> Search Directory Objects
                    </div>
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <input type="text" class="form-control" id="directorySearch" placeholder="Search users, groups, or computers..." onkeyup="filterDirectoryObjects()">
                            <button class="btn btn-outline-secondary" type="button" onclick="clearDirectorySearch()">
                                <i class="fas fa-times"></i> Clear
                            </button>
                        </div>
                        <div class="btn-group" role="group">
                            <input type="radio" class="btn-check" name="objectTypeFilter" id="filterAll" value="all" checked onchange="filterDirectoryObjects()">
                            <label class="btn btn-outline-primary" for="filterAll">All</label>
                            
                            <input type="radio" class="btn-check" name="objectTypeFilter" id="filterUsers" value="users" onchange="filterDirectoryObjects()">
                            <label class="btn btn-outline-primary" for="filterUsers">Users</label>
                            
                            <input type="radio" class="btn-check" name="objectTypeFilter" id="filterGroups" value="groups" onchange="filterDirectoryObjects()">
                            <label class="btn btn-outline-primary" for="filterGroups">Groups</label>
                            
                            <input type="radio" class="btn-check" name="objectTypeFilter" id="filterComputers" value="computers" onchange="filterDirectoryObjects()">
                            <label class="btn btn-outline-primary" for="filterComputers">Computers</label>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Users Table -->
        <div class="row mb-4" id="usersSection">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-users"></i> Users ({len(users_data)})</span>
                        <button class="btn btn-sm btn-success" onclick="exportToExcel('users')">
                            <i class="fas fa-file-excel"></i> Export to Excel
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="usersTable">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Display Name</th>
                                        <th>Status</th>
                                        <th>Last Logon</th>
                                        <th>Account Age</th>
                                        <th>Admin Groups</th>
                                        <th>SPN</th>
                                        <th>Service Account</th>
                                        <th>Groups</th>
                                        <th>Risk Count</th>
                                        <th>Critical Risks</th>
                                        <th>Privileged</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="usersTableBody">
                                    {''.join(users_rows[:dir_page_size])}
                                </tbody>
                            </table>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mt-2" id="usersTablePagination">
                            <small class="text-muted" id="usersTableInfo">Showing 1-{min(dir_page_size, len(users_rows))} of {len(users_rows)}</small>
                            <nav><ul class="pagination pagination-sm mb-0">
                                <li class="page-item disabled" id="usersTablePrev"><a class="page-link" href="#" onclick="changeDirectoryTablePage('users', -1); return false;">Previous</a></li>
                                <li class="page-item"><span class="page-link" id="usersTablePageInfo">Page 1 of {max(1, (len(users_rows) + dir_page_size - 1) // dir_page_size)}</span></li>
                                <li class="page-item {'disabled' if len(users_rows) <= dir_page_size else ''}" id="usersTableNext"><a class="page-link" href="#" onclick="changeDirectoryTablePage('users', 1); return false;">Next</a></li>
                            </ul></nav>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Groups Table -->
        <div class="row mb-4" id="groupsSection">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-users-cog"></i> Groups ({len(groups_data)})</span>
                        <button class="btn btn-sm btn-success" onclick="exportToExcel('groups')">
                            <i class="fas fa-file-excel"></i> Export to Excel
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="groupsTable">
                                <thead>
                                    <tr>
                                        <th>Group Name</th>
                                        <th>Members</th>
                                        <th>Risk Count</th>
                                        <th>Critical Risks</th>
                                        <th>Privileged</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="groupsTableBody">
                                    {''.join(groups_rows[:dir_page_size])}
                                </tbody>
                            </table>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mt-2" id="groupsTablePagination">
                            <small class="text-muted" id="groupsTableInfo">Showing 1-{min(dir_page_size, len(groups_rows))} of {len(groups_rows)}</small>
                            <nav><ul class="pagination pagination-sm mb-0">
                                <li class="page-item disabled" id="groupsTablePrev"><a class="page-link" href="#" onclick="changeDirectoryTablePage('groups', -1); return false;">Previous</a></li>
                                <li class="page-item"><span class="page-link" id="groupsTablePageInfo">Page 1 of {max(1, (len(groups_rows) + dir_page_size - 1) // dir_page_size)}</span></li>
                                <li class="page-item {'disabled' if len(groups_rows) <= dir_page_size else ''}" id="groupsTableNext"><a class="page-link" href="#" onclick="changeDirectoryTablePage('groups', 1); return false;">Next</a></li>
                            </ul></nav>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Computers Table -->
        <div class="row mb-4" id="computersSection">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-server"></i> Computers ({len(computers_data)})</span>
                        <button class="btn btn-sm btn-success" onclick="exportToExcel('computers')">
                            <i class="fas fa-file-excel"></i> Export to Excel
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="computersTable">
                                <thead>
                                    <tr>
                                        <th>Computer Name</th>
                                        <th>Operating System</th>
                                        <th>Risk Count</th>
                                        <th>Critical Risks</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="computersTableBody">
                                    {''.join(computers_rows[:dir_page_size])}
                                </tbody>
                            </table>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mt-2" id="computersTablePagination">
                            <small class="text-muted" id="computersTableInfo">Showing 1-{min(dir_page_size, len(computers_rows))} of {len(computers_rows)}</small>
                            <nav><ul class="pagination pagination-sm mb-0">
                                <li class="page-item disabled" id="computersTablePrev"><a class="page-link" href="#" onclick="changeDirectoryTablePage('computers', -1); return false;">Previous</a></li>
                                <li class="page-item"><span class="page-link" id="computersTablePageInfo">Page 1 of {max(1, (len(computers_rows) + dir_page_size - 1) // dir_page_size)}</span></li>
                                <li class="page-item {'disabled' if len(computers_rows) <= dir_page_size else ''}" id="computersTableNext"><a class="page-link" href="#" onclick="changeDirectoryTablePage('computers', 1); return false;">Next</a></li>
                            </ul></nav>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Object Detail Modal -->
        <div class="modal fade" id="objectDetailModal" tabindex="-1" aria-labelledby="objectDetailModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="objectDetailModalLabel">
                            <i class="fas fa-info-circle"></i> Object Details
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="objectDetailContent" style="max-height: 70vh; overflow-y: auto;">
                        <!-- Content will be loaded dynamically -->
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            <i class="fas fa-times"></i> Close
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // XSS prevention: escape user-controlled data before inserting into innerHTML
        function escapeHtml(str) {{
            if (str == null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }}
        
        // Directory data and pagination
        window.directoryTableRows = {json.dumps({"users": users_rows, "groups": groups_rows, "computers": computers_rows})};
        window.dirPageSize = {dir_page_size};
        window.directoryTablePages = {{ users: 0, groups: 0, computers: 0 }};
        window.directoryTableFiltered = {{ users: null, groups: null, computers: null }};
        
        const directoryData = {{
            users: {json.dumps(users_data, default=json_serializer)},
            groups: {json.dumps(groups_data, default=json_serializer)},
            computers: {json.dumps(computers_data, default=json_serializer)},
            allUsers: {json.dumps(clean_for_json(users), default=json_serializer)},
            allGroups: {json.dumps(clean_for_json(groups), default=json_serializer)},
            allComputers: {json.dumps(clean_for_json(computers), default=json_serializer)},
            allRisks: {json.dumps(clean_for_json(risks), default=json_serializer)}
        }};
        
        function changeDirectoryTablePage(tableType, delta) {{
            const pages = window.directoryTablePages;
            const pageSize = window.dirPageSize;
            let rows = window.directoryTableFiltered[tableType] || window.directoryTableRows[tableType];
            const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
            const newPage = Math.max(0, Math.min(pages[tableType] + delta, totalPages - 1));
            pages[tableType] = newPage;
            
            const start = newPage * pageSize;
            const pageRows = rows.slice(start, start + pageSize);
            const tbody = document.getElementById(tableType + 'TableBody');
            const infoEl = document.getElementById(tableType + 'TableInfo');
            const pageInfoEl = document.getElementById(tableType + 'TablePageInfo');
            const prevBtn = document.getElementById(tableType + 'TablePrev');
            const nextBtn = document.getElementById(tableType + 'TableNext');
            
            tbody.innerHTML = pageRows.join('');
            
            const from = rows.length ? start + 1 : 0;
            const to = Math.min(start + pageSize, rows.length);
            infoEl.textContent = 'Showing ' + from + '-' + to + ' of ' + rows.length;
            pageInfoEl.textContent = 'Page ' + (newPage + 1) + ' of ' + totalPages;
            
            prevBtn.classList.toggle('disabled', newPage <= 0);
            nextBtn.classList.toggle('disabled', newPage >= totalPages - 1);
        }}
        
        function filterDirectoryObjects() {{
            const searchTerm = document.getElementById('directorySearch').value.toLowerCase();
            const filterType = document.querySelector('input[name="objectTypeFilter"]:checked').value;
            
            function filterRows(rows) {{
                if (!searchTerm) return null;
                return rows.filter(html => {{
                    const div = document.createElement('div');
                    div.innerHTML = html;
                    return div.textContent.toLowerCase().includes(searchTerm);
                }});
            }}
            
            // Update filtered data and reset to page 0
            window.directoryTableFiltered.users = filterRows(window.directoryTableRows.users);
            window.directoryTableFiltered.groups = filterRows(window.directoryTableRows.groups);
            window.directoryTableFiltered.computers = filterRows(window.directoryTableRows.computers);
            window.directoryTablePages = {{ users: 0, groups: 0, computers: 0 }};
            
            // Visibility
            document.getElementById('usersSection').style.display = (filterType === 'all' || filterType === 'users') ? '' : 'none';
            document.getElementById('groupsSection').style.display = (filterType === 'all' || filterType === 'groups') ? '' : 'none';
            document.getElementById('computersSection').style.display = (filterType === 'all' || filterType === 'computers') ? '' : 'none';
            
            // Re-render all tables with filtered data
            ['users', 'groups', 'computers'].forEach(t => changeDirectoryTablePage(t, 0));
        }}
        
        function clearDirectorySearch() {{
            document.getElementById('directorySearch').value = '';
            filterDirectoryObjects();
        }}
        
        // Enhanced Search and Filter Functionality
        (function() {{
            'use strict';
            
            // Debounce function for search
            function debounce(func, wait) {{
                let timeout;
                return function executedFunction(...args) {{
                    const later = () => {{
                        clearTimeout(timeout);
                        func(...args);
                    }};
                    clearTimeout(timeout);
                    timeout = setTimeout(later, wait);
                }};
            }}
            
            // Enhanced search functionality
            function handleSearch(searchId, containerId) {{
                const searchInput = document.getElementById(searchId);
                const severityFilter = document.getElementById(searchId + '_severity');
                const typeFilter = document.getElementById(searchId + '_type');
                const sortBy = document.getElementById(searchId + '_sort');
                const resultsCount = document.getElementById(searchId + '_results');
                
                if (!searchInput) return;
                
                const searchTerm = searchInput.value.toLowerCase();
                const severityValue = severityFilter ? severityFilter.value : '';
                const typeValue = typeFilter ? typeFilter.value : '';
                const sortValue = sortBy ? sortBy.value : 'score-desc';
                
                const container = document.getElementById(containerId);
                if (!container) return;
                
                const riskCards = container.querySelectorAll('.risk-card');
                let visibleCount = 0;
                
                riskCards.forEach(card => {{
                    const title = card.querySelector('.risk-title')?.textContent.toLowerCase() || '';
                    const description = card.querySelector('.risk-card-body')?.textContent.toLowerCase() || '';
                    const affected = card.querySelector('.risk-object')?.textContent.toLowerCase() || '';
                    const severity = card.dataset.severity || '';
                    const type = card.dataset.type || '';
                    
                    const matchesSearch = !searchTerm || 
                        title.includes(searchTerm) || 
                        description.includes(searchTerm) || 
                        affected.includes(searchTerm);
                    const matchesSeverity = !severityValue || severity === severityValue;
                    const matchesType = !typeValue || type === typeValue;
                    
                    if (matchesSearch && matchesSeverity && matchesType) {{
                        card.style.display = '';
                        visibleCount++;
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});
                
                // Update results count
                if (resultsCount) {{
                    resultsCount.textContent = `Showing ${{visibleCount}} of ${{riskCards.length}} risks`;
                }}
                
                // Sort results
                sortRiskCards(containerId, sortValue);
            }}
            
            // Sort risk cards
            function sortRiskCards(containerId, sortBy) {{
                const container = document.getElementById(containerId);
                if (!container) return;
                
                const cards = Array.from(container.querySelectorAll('.risk-card'));
                const visibleCards = cards.filter(card => card.style.display !== 'none');
                
                visibleCards.sort((a, b) => {{
                    switch(sortBy) {{
                        case 'score-desc':
                            return parseFloat(b.dataset.score || 0) - parseFloat(a.dataset.score || 0);
                        case 'score-asc':
                            return parseFloat(a.dataset.score || 0) - parseFloat(b.dataset.score || 0);
                        case 'title-asc':
                            const titleA = a.querySelector('.risk-title')?.textContent || '';
                            const titleB = b.querySelector('.risk-title')?.textContent || '';
                            return titleA.localeCompare(titleB);
                        case 'title-desc':
                            const titleA2 = a.querySelector('.risk-title')?.textContent || '';
                            const titleB2 = b.querySelector('.risk-title')?.textContent || '';
                            return titleB2.localeCompare(titleA2);
                        default:
                            return 0;
                    }}
                }});
                
                // Reorder visible cards
                visibleCards.forEach(card => container.appendChild(card));
            }}
            
            // Initialize search handlers for all risk sections (only input elements, not export buttons)
            document.addEventListener('DOMContentLoaded', function() {{
                const searchInputs = document.querySelectorAll('input[id^="search_"]');
                searchInputs.forEach(input => {{
                    const searchId = input.id;
                    const containerId = searchId.replace('search_', 'risks_container_');
                    
                    // Add event listeners
                    input.addEventListener('input', debounce(() => handleSearch(searchId, containerId), 300));
                    
                    // Add filter listeners
                    const severityFilter = document.getElementById(searchId + '_severity');
                    const typeFilter = document.getElementById(searchId + '_type');
                    const sortBy = document.getElementById(searchId + '_sort');
                    
                    if (severityFilter) {{
                        severityFilter.addEventListener('change', () => handleSearch(searchId, containerId));
                    }}
                    if (typeFilter) {{
                        typeFilter.addEventListener('change', () => handleSearch(searchId, containerId));
                    }}
                    if (sortBy) {{
                        sortBy.addEventListener('change', () => handleSearch(searchId, containerId));
                    }}
    
                    // Wire Export button for this risk section
                    const exportBtn = document.getElementById(searchId + '_export');
                    if (exportBtn) {{
                        exportBtn.addEventListener('click', () => exportRiskSectionToCsv(containerId, searchId));
                    }}
                }});
            }});
        }})();
    
        // Export risk section (visible/filtered risk cards) to CSV
        function exportRiskSectionToCsv(containerId, sectionId) {{
            const container = document.getElementById(containerId);
            if (!container) {{ console.error('Container not found:', containerId); return; }}
            const cards = Array.from(container.querySelectorAll('.risk-card')).filter(c => c.style.display !== 'none');
            const timestamp = new Date().toISOString().slice(0,19).replace(/:/g, '-');
            const sectionName = (sectionId || containerId).replace('search_', '').replace('risks_container_', '') || 'Risks';
            const filename = `AtilKurt_${{sectionName}}_${{timestamp}}.csv`;
            let csv = ['"Title","Severity","Type","Affected Object","Score","Description"'];
            cards.forEach(card => {{
                const title = (card.querySelector('.risk-title')?.textContent || card.querySelector('.card-title')?.textContent || '').replace(/"/g, '""');
                const severity = (card.dataset.severity || card.querySelector('.badge')?.textContent || '').replace(/"/g, '""');
                const type = (card.dataset.type || '').replace(/"/g, '""');
                const affected = (card.querySelector('.risk-object')?.textContent || '').replace(/"/g, '""');
                const score = (card.dataset.score || '');
                const bodyEl = card.querySelector('.risk-card-body') || card.querySelector('.card-body');
                const desc = (bodyEl?.textContent || '').slice(0, 200).replace(/"/g, '""').replace(/\\n/g, ' ');
                csv.push(`"${{title}}","${{severity}}","${{type}}","${{affected}}","${{score}}","${{desc}}"`);
            }});
            const blob = new Blob([csv.join('\\n')], {{ type: 'text/csv;charset=utf-8;' }});
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
        }};
        if (typeof window !== 'undefined') window.exportRiskSectionToCsv = exportRiskSectionToCsv;
        
        // Export single risk card to CSV (for per-card Export button)
        function exportSingleRiskToCsv(btn) {{
            const card = btn.closest('.risk-card');
            if (!card) return;
            const title = (card.querySelector('.risk-title')?.textContent || card.querySelector('.card-title')?.textContent || '').replace(/"/g, '""');
            const severity = (card.dataset.severity || card.querySelector('.badge')?.textContent || '').replace(/"/g, '""');
            const type = (card.dataset.type || '').replace(/"/g, '""');
            const affected = (card.querySelector('.risk-object')?.textContent || '').replace(/"/g, '""');
            const score = card.dataset.score || '';
            const bodyEl = card.querySelector('.risk-card-body') || card.querySelector('.card-body');
            const desc = (bodyEl?.textContent || '').slice(0, 500).replace(/"/g, '""').replace(/\\n/g, ' ');
            const csv = ['"Title","Severity","Type","Affected Object","Score","Description"', `"${{title}}","${{severity}}","${{type}}","${{affected}}","${{score}}","${{desc}}"`];
            const timestamp = new Date().toISOString().slice(0,19).replace(/:/g, '-');
            const safeTitle = title.slice(0, 30).replace(/[^a-zA-Z0-9]/g, '_');
            const filename = `AtilKurt_Risk_${{safeTitle}}_${{timestamp}}.csv`;
            const blob = new Blob([csv.join('\\n')], {{ type: 'text/csv;charset=utf-8;' }});
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
        }};
        if (typeof window !== 'undefined') window.exportSingleRiskToCsv = exportSingleRiskToCsv;
        
        // Legacy compatibility functions
        function filterRisks(searchId, containerId) {{
            const searchInput = document.getElementById(searchId);
            if (searchInput) {{
                searchInput.dispatchEvent(new Event('input'));
            }}
        }}
        
        function clearRiskSearch(searchId, containerId) {{
            const searchInput = document.getElementById(searchId);
            const severityFilter = document.getElementById(searchId + '_severity');
            const typeFilter = document.getElementById(searchId + '_type');
            const sortBy = document.getElementById(searchId + '_sort');
            
            if (searchInput) searchInput.value = '';
            if (severityFilter) severityFilter.value = '';
            if (typeFilter) typeFilter.value = '';
            if (sortBy) sortBy.value = 'score-desc';
            
            filterRisks(searchId, containerId);
        }}
        
        // Attack paths search
        function filterAttackPaths() {{
            const searchTerm = document.getElementById('attackPathsSearch').value.toLowerCase();
            const container = document.getElementById('attackPathsContainer');
            if (!container) return;
            
            const pathCards = container.querySelectorAll('.card.risk-card');
            pathCards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        function clearAttackPathsSearch() {{
            document.getElementById('attackPathsSearch').value = '';
            filterAttackPaths();
        }}
        
        // Misconfig search
        function filterMisconfig() {{
            const searchTerm = document.getElementById('misconfigSearch').value.toLowerCase();
            const container = document.getElementById('misconfigContainer');
            if (!container) return;
            
            const findingCards = container.querySelectorAll('.card.risk-card');
            findingCards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        function clearMisconfigSearch() {{
            document.getElementById('misconfigSearch').value = '';
            filterMisconfig();
        }}
        
        // Password issues preview search
        function filterPasswordIssuesPreview() {{
            const searchTerm = document.getElementById('passwordIssuesPreviewSearch').value.toLowerCase();
            const table = document.getElementById('passwordIssuesPreviewTable');
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        function clearPasswordIssuesPreviewSearch() {{
            document.getElementById('passwordIssuesPreviewSearch').value = '';
            filterPasswordIssuesPreview();
        }}
        
        // Password issues full search
        function filterPasswordIssuesFull() {{
            const searchTerm = document.getElementById('passwordIssuesFullSearch').value.toLowerCase();
            const table = document.getElementById('passwordIssuesFullTable');
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        function clearPasswordIssuesFullSearch() {{
            document.getElementById('passwordIssuesFullSearch').value = '';
            filterPasswordIssuesFull();
        }}
        
        // Kerberoasting search
        function filterKerberoasting() {{
            const searchTerm = document.getElementById('kerberoastingSearch').value.toLowerCase();
            const container = document.getElementById('kerberoastingContainer');
            if (!container) return;
            
            const riskCards = container.querySelectorAll('.card.risk-card');
            riskCards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        function clearKerberoastingSearch() {{
            document.getElementById('kerberoastingSearch').value = '';
            filterKerberoasting();
        }}
        
        function showUserDetails(username) {{
            const user = directoryData.allUsers.find(u => u.sAMAccountName === username);
            if (!user) return;
            
            // Get user data from users_data array for group memberships
            const userData = directoryData.users.find(u => u.sAMAccountName === username);
            const userRisks = directoryData.allRisks.filter(r => r.affected_object === username);
            
            // Get group memberships
            let groups = [];
            if (userData && userData.groups && userData.groups.length > 0) {{
                groups = userData.groups;
            }} else {{
                const memberOf = user.memberOf || [];
                const memberOfList = Array.isArray(memberOf) ? memberOf : [memberOf];
                groups = memberOfList.map(groupDn => {{
                    if (typeof groupDn === 'string' && groupDn.includes('CN=')) {{
                        try {{
                            return groupDn.split('CN=')[1].split(',')[0];
                        }} catch(e) {{
                            return groupDn;
                        }}
                    }}
                    return groupDn;
                }});
            }}
            
            const isPrivileged = user.adminCount == 1 || user.adminCount == '1' || 
                                groups.some(g => g.toUpperCase().includes('DOMAIN ADMINS') || 
                                              g.toUpperCase().includes('ENTERPRISE ADMINS'));
            
            // Get admin groups from memberOf
            const domainAdminGroups = [];
            const enterpriseAdminGroups = [];
            const schemaAdminGroups = [];
            const memberOf = user.memberOf || [];
            const memberOfList = Array.isArray(memberOf) ? memberOf : [memberOf];
            memberOfList.forEach(groupDn => {{
                if (!groupDn) return;
                const groupStr = String(groupDn).toUpperCase();
                let groupName = groupDn;
                if (typeof groupDn === 'string' && groupDn.includes('CN=')) {{
                    try {{
                        groupName = groupDn.split('CN=')[1].split(',')[0];
                    }} catch(e) {{
                        groupName = groupDn;
                    }}
                }}
                if (groupStr.includes('DOMAIN ADMINS')) {{
                    domainAdminGroups.push(groupName);
                }}
                if (groupStr.includes('ENTERPRISE ADMINS')) {{
                    enterpriseAdminGroups.push(groupName);
                }}
                if (groupStr.includes('SCHEMA ADMINS')) {{
                    schemaAdminGroups.push(groupName);
                }}
            }});
            
            // Format last logon
            let lastLogon = 'N/A';
            let daysSinceLastLogon = null;
            if (user.lastLogonTimestamp) {{
                try {{
                    const logonDate = new Date(user.lastLogonTimestamp);
                    lastLogon = logonDate.toLocaleString();
                    const now = new Date();
                    daysSinceLastLogon = Math.floor((now - logonDate) / (1000 * 60 * 60 * 24));
                }} catch(e) {{
                    lastLogon = user.lastLogonTimestamp;
                }}
            }}
            
            // Account status
            const isDisabled = user.isDisabled || false;
            const isLocked = user.isLocked || false;
            let statusBadge = '<span class="badge bg-success">Active</span>';
            if (isDisabled) {{
                statusBadge = '<span class="badge bg-secondary">Disabled</span>';
            }}
            if (isLocked) {{
                statusBadge = '<span class="badge bg-danger">Locked</span>';
            }}
            
            // SPN information
            const spns = user.servicePrincipalName || [];
            const hasSPN = spns.length > 0;
            
            // Service account information
            const isServiceAccount = user.isServiceAccount || false;
            const passwordNeverExpires = (user.userAccountControl & 0x10000) !== 0;
            const isServiceWithPwdNeverExpires = isServiceAccount && passwordNeverExpires;
            
            // Account age
            let accountAge = 'N/A';
            if (user.accountAgeDays !== undefined && user.accountAgeDays !== null) {{
                accountAge = `${{user.accountAgeDays}} days`;
            }}
            
            // Admin privilege age
            let adminPrivilegeAge = 'N/A';
            if (user.adminPrivilegeAgeDays !== undefined && user.adminPrivilegeAgeDays !== null) {{
                adminPrivilegeAge = `${{user.adminPrivilegeAgeDays}} days`;
            }}
            
            // Recently created/modified flags
            const createdInLast10Days = user.createdInLast10Days || false;
            const createdInLast30Days = user.createdInLast30Days || false;
            const createdInLast60Days = user.createdInLast60Days || false;
            const createdInLast90Days = user.createdInLast90Days || false;
            const groupChangedInLast10Days = user.groupChangedInLast10Days || false;
            const groupChangedInLast30Days = user.groupChangedInLast30Days || false;
            const groupChangedInLast60Days = user.groupChangedInLast60Days || false;
            const groupChangedInLast90Days = user.groupChangedInLast90Days || false;
            
            // Format account creation date
            let accountCreated = 'N/A';
            if (user.whenCreated) {{
                try {{
                    const createdDate = new Date(user.whenCreated);
                    accountCreated = createdDate.toLocaleString();
                }} catch(e) {{
                    accountCreated = user.whenCreated;
                }}
            }}
            
            // Format password last set
            let passwordLastSet = 'N/A';
            let passwordAge = null;
            if (user.pwdLastSet) {{
                try {{
                    const pwdDate = new Date(user.pwdLastSet);
                    passwordLastSet = pwdDate.toLocaleString();
                    const now = new Date();
                    passwordAge = Math.floor((now - pwdDate) / (1000 * 60 * 60 * 24));
                }} catch(e) {{
                    passwordLastSet = user.pwdLastSet;
                    passwordAge = null;
                }}
            }}
            
            // Build groups HTML with modern styling
            let groupsHtml = '';
            if (groups.length > 0) {{
                groupsHtml = '<div class="row">';
                groups.forEach((group, index) => {{
                    const isPrivGroup = group.toUpperCase().includes('DOMAIN ADMINS') ||
                                       group.toUpperCase().includes('ENTERPRISE ADMINS') ||
                                       group.toUpperCase().includes('SCHEMA ADMINS');
                    groupsHtml += `
                        <div class="col-md-4 col-sm-6 mb-2">
                            <div class="badge bg-${{isPrivGroup ? 'danger' : 'light'}} text-${{isPrivGroup ? 'white' : 'dark'}} border">
                                <i class="fas fa-users-cog"></i> ${{escapeHtml(group)}}
                            </div>
                        </div>
                    `;
                }});
                groupsHtml += '</div>';
            }} else {{
                groupsHtml = '<p class="text-muted"><i class="fas fa-info-circle"></i> This user is not a member of any groups.</p>';
            }}
            
            // Build risks HTML with modern styling
            let risksHtml = '';
            if (userRisks.length > 0) {{
                risksHtml = '<div class="row">';
                userRisks.forEach(risk => {{
                    const severity = risk.severity || risk.severity_level || 'Medium';
                    const badgeColor = {{
                        'Critical': 'danger',
                        'High': 'warning',
                        'Medium': 'info',
                        'Low': 'success'
                    }}[severity] || 'secondary';
                    const icon = {{
                        'Critical': 'exclamation-triangle',
                        'High': 'exclamation-circle',
                        'Medium': 'info-circle',
                        'Low': 'check-circle'
                    }}[severity] || 'info-circle';
                    
                    risksHtml += `
                        <div class="col-12 mb-2">
                            <div class="card border-${{badgeColor}}">
                                <div class="card-body p-2">
                                    <span class="badge bg-${{badgeColor}} me-2">
                                        <i class="fas fa-${{icon}}"></i> ${{escapeHtml(severity)}}
                                    </span>
                                    <strong>${{escapeHtml(risk.type || risk.title || 'Unknown Risk')}}</strong>
                                    ${{risk.description ? '<p class="mb-0 mt-1 small text-muted">' + escapeHtml(risk.description.substring(0, 150)) + '</p>' : ''}}
                                </div>
                            </div>
                        </div>
                    `;
                }});
                risksHtml += '</div>';
            }} else {{
                risksHtml = '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No risks found for this user.</div>';
            }}
            
            // Build modern modal content (escapeHtml prevents XSS from LDAP data)
            document.getElementById('objectDetailModalLabel').innerHTML = `
                <i class="fas fa-user text-primary"></i> User Details: <strong>${{escapeHtml(username)}}</strong>
            `;
            document.getElementById('objectDetailContent').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-primary text-white">
                                <i class="fas fa-info-circle"></i> User Information
                            </div>
                            <div class="card-body">
                                <table class="table table-sm table-borderless mb-0">
                                    <tr>
                                        <td width="40%"><strong><i class="fas fa-user"></i> Username:</strong></td>
                                        <td>${{escapeHtml(user.sAMAccountName || 'N/A')}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-id-card"></i> Display Name:</strong></td>
                                        <td>${{escapeHtml(user.displayName || user.sAMAccountName || 'N/A')}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-info-circle"></i> Account Status:</strong></td>
                                        <td>${{statusBadge}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-shield-alt"></i> Admin Count:</strong></td>
                                        <td>${{user.adminCount == 1 || user.adminCount == '1' ? '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle"></i> Yes</span>' : '<span class="badge bg-success"><i class="fas fa-check"></i> No</span>'}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-crown"></i> Privileged:</strong></td>
                                        <td>${{isPrivileged ? '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle"></i> Yes</span>' : '<span class="badge bg-success"><i class="fas fa-check"></i> No</span>'}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-clock"></i> Last Logon:</strong></td>
                                        <td>${{escapeHtml(lastLogon)}} ${{daysSinceLastLogon !== null ? (daysSinceLastLogon >= 90 ? '<span class="badge bg-danger">' + escapeHtml(String(daysSinceLastLogon)) + ' days ago</span>' : daysSinceLastLogon >= 30 ? '<span class="badge bg-warning">' + escapeHtml(String(daysSinceLastLogon)) + ' days ago</span>' : '<span class="badge bg-info">' + escapeHtml(String(daysSinceLastLogon)) + ' days ago</span>') : ''}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-calendar-alt"></i> Account Age:</strong></td>
                                        <td>${{escapeHtml(accountAge)}}</td>
                                    </tr>
                                    ${{adminPrivilegeAge !== 'N/A' ? `<tr><td><strong><i class="fas fa-user-shield"></i> Admin Privilege Age:</strong></td><td>${{escapeHtml(adminPrivilegeAge)}}</td></tr>` : ''}}
                                    ${{hasSPN ? `<tr><td><strong><i class="fas fa-key"></i> Service Principal Names:</strong></td><td><span class="badge bg-warning">${{spns.length}} SPN(s)</span></td></tr>` : ''}}
                                    ${{isServiceAccount ? `<tr><td><strong><i class="fas fa-server"></i> Service Account:</strong></td><td><span class="badge bg-info">Yes</span> ${{isServiceWithPwdNeverExpires ? '<span class="badge bg-danger">Password Never Expires</span>' : ''}}</td></tr>` : ''}}
                                    ${{domainAdminGroups.length > 0 ? `<tr><td><strong><i class="fas fa-users-cog"></i> Domain Admin Groups:</strong></td><td><span class="badge bg-danger">${{domainAdminGroups.length}} group(s)</span></td></tr>` : ''}}
                                    ${{enterpriseAdminGroups.length > 0 ? `<tr><td><strong><i class="fas fa-users-cog"></i> Enterprise Admin Groups:</strong></td><td><span class="badge bg-danger">${{enterpriseAdminGroups.length}} group(s)</span></td></tr>` : ''}}
                                    ${{schemaAdminGroups.length > 0 ? `<tr><td><strong><i class="fas fa-users-cog"></i> Schema Admin Groups:</strong></td><td><span class="badge bg-danger">${{schemaAdminGroups.length}} group(s)</span></td></tr>` : ''}}
                                    ${{createdInLast10Days || createdInLast30Days || createdInLast60Days || createdInLast90Days ? `<tr><td><strong><i class="fas fa-calendar-plus"></i> Recently Created:</strong></td><td>${{createdInLast10Days ? '<span class="badge bg-warning">Last 10 days</span>' : createdInLast30Days ? '<span class="badge bg-info">Last 30 days</span>' : createdInLast60Days ? '<span class="badge bg-info">Last 60 days</span>' : '<span class="badge bg-info">Last 90 days</span>'}}</td></tr>` : ''}}
                                    ${{groupChangedInLast10Days || groupChangedInLast30Days || groupChangedInLast60Days || groupChangedInLast90Days ? `<tr><td><strong><i class="fas fa-exchange-alt"></i> Group Changed:</strong></td><td>${{groupChangedInLast10Days ? '<span class="badge bg-warning">Last 10 days</span>' : groupChangedInLast30Days ? '<span class="badge bg-info">Last 30 days</span>' : groupChangedInLast60Days ? '<span class="badge bg-info">Last 60 days</span>' : '<span class="badge bg-info">Last 90 days</span>'}}</td></tr>` : ''}}
                                    <tr>
                                        <td><strong><i class="fas fa-calendar-plus"></i> Account Created:</strong></td>
                                        <td>${{escapeHtml(accountCreated)}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-key"></i> Password Last Set:</strong></td>
                                        <td>
                                            ${{escapeHtml(passwordLastSet)}}
                                            ${{passwordAge !== null && passwordAge !== undefined ? (passwordAge > 90 ? '<span class="badge bg-danger ms-2"><i class="fas fa-exclamation-triangle"></i> ' + escapeHtml(String(passwordAge)) + ' days old</span>' : passwordAge > 60 ? '<span class="badge bg-warning ms-2">' + escapeHtml(String(passwordAge)) + ' days old</span>' : '<span class="badge bg-success ms-2">' + escapeHtml(String(passwordAge)) + ' days old</span>') : ''}}
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-exclamation-triangle"></i> Risk Count:</strong></td>
                                        <td><span class="badge bg-${{userRisks.length > 0 ? 'warning' : 'success'}}">${{userRisks.length}}</span></td>
                                    </tr>
                                    ${{user.description ? `<tr><td><strong><i class="fas fa-align-left"></i> Description:</strong></td><td>${{escapeHtml(user.description)}}</td></tr>` : ''}}
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-secondary text-white">
                                <i class="fas fa-chart-bar"></i> Statistics
                            </div>
                            <div class="card-body">
                                <div class="row text-center">
                                    <div class="col-6">
                                        <h4 class="text-primary">${{groups.length}}</h4>
                                        <small class="text-muted">Groups</small>
                                    </div>
                                    <div class="col-6">
                                        <h4 class="text-${{userRisks.length > 0 ? 'warning' : 'success'}}">${{userRisks.length}}</h4>
                                        <small class="text-muted">Risks</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <i class="fas fa-users-cog"></i> Group Memberships (${{groups.length}})
                            </div>
                            <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                                ${{groupsHtml}}
                            </div>
                        </div>
                    </div>
                </div>
                
                ${{domainAdminGroups.length > 0 || enterpriseAdminGroups.length > 0 || schemaAdminGroups.length > 0 ? `
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-danger text-white">
                                <i class="fas fa-shield-alt"></i> Admin Group Memberships
                            </div>
                            <div class="card-body">
                                ${{domainAdminGroups.length > 0 ? `<div class="mb-2"><strong>Domain Admin Groups:</strong><br>` + domainAdminGroups.map(g => `<span class="badge bg-danger me-1">${{g}}</span>`).join('') + '</div>' : ''}}
                                ${{enterpriseAdminGroups.length > 0 ? `<div class="mb-2"><strong>Enterprise Admin Groups:</strong><br>` + enterpriseAdminGroups.map(g => `<span class="badge bg-danger me-1">${{g}}</span>`).join('') + '</div>' : ''}}
                                ${{schemaAdminGroups.length > 0 ? `<div class="mb-2"><strong>Schema Admin Groups:</strong><br>` + schemaAdminGroups.map(g => `<span class="badge bg-danger me-1">${{g}}</span>`).join('') + '</div>' : ''}}
                            </div>
                        </div>
                    </div>
                </div>
                ` : ''}}
                
                ${{hasSPN ? `
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-warning text-dark">
                                <i class="fas fa-key"></i> Service Principal Names (${{spns.length}})
                            </div>
                            <div class="card-body" style="max-height: 200px; overflow-y: auto;">
                                <ul class="list-unstyled mb-0">
                                    ${{spns.map(spn => `<li><code>${{spn}}</code></li>`).join('')}}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                ` : ''}}
                
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-${{userRisks.length > 0 ? 'warning' : 'success'}} text-white">
                                <i class="fas fa-exclamation-triangle"></i> Security Risks (${{userRisks.length}})
                            </div>
                            <div class="card-body">
                                ${{risksHtml}}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            const modal = new bootstrap.Modal(document.getElementById('objectDetailModal'));
            modal.show();
        }}
        
        function showGroupDetails(groupName) {{
            const group = directoryData.allGroups.find(g => g.name === groupName);
            if (!group) return;
            
            // Get group data from groups_data array
            const groupData = directoryData.groups.find(g => g.name === groupName);
            const groupRisks = directoryData.allRisks.filter(r => r.affected_object === groupName);
            
            // Get members - try multiple sources
            let memberList = [];
            if (groupData && groupData.members && groupData.members.length > 0) {{
                memberList = groupData.members;
            }} else if (group.member && group.member.length > 0) {{
                // Extract CN from DN
                const members = Array.isArray(group.member) ? group.member : [group.member];
                memberList = members.map(memberDn => {{
                    if (typeof memberDn === 'string' && memberDn.includes('CN=')) {{
                        try {{
                            return memberDn.split('CN=')[1].split(',')[0];
                        }} catch(e) {{
                            return memberDn;
                        }}
                    }}
                    return memberDn;
                }});
            }} else if (group.members && group.members.length > 0) {{
                const members = Array.isArray(group.members) ? group.members : [group.members];
                memberList = members.map(memberDn => {{
                    if (typeof memberDn === 'string' && memberDn.includes('CN=')) {{
                        try {{
                            return memberDn.split('CN=')[1].split(',')[0];
                        }} catch(e) {{
                            return memberDn;
                        }}
                    }}
                    return memberDn;
                }});
            }}
            
            const memberCount = memberList.length;
            const isPrivileged = group.isPrivileged || group.is_privileged || 
                                groupName.toUpperCase().includes('DOMAIN ADMINS') ||
                                groupName.toUpperCase().includes('ENTERPRISE ADMINS') ||
                                groupName.toUpperCase().includes('SCHEMA ADMINS');
            
            // Build members HTML with modern styling
            let membersHtml = '';
            if (memberCount > 0) {{
                membersHtml = '<div class="row">';
                memberList.slice(0, 100).forEach((member, index) => {{
                    membersHtml += `
                        <div class="col-md-4 col-sm-6 mb-2">
                            <div class="badge bg-light text-dark border">
                                <i class="fas fa-user"></i> ${{escapeHtml(member)}}
                            </div>
                        </div>
                    `;
                }});
                if (memberCount > 100) {{
                    membersHtml += `
                        <div class="col-12">
                            <p class="text-muted"><em>... and ${{memberCount - 100}} more members</em></p>
                        </div>
                    `;
                }}
                membersHtml += '</div>';
            }} else {{
                membersHtml = '<p class="text-muted"><i class="fas fa-info-circle"></i> This group has no members.</p>';
            }}
            
            // Build risks HTML with modern styling
            let risksHtml = '';
            if (groupRisks.length > 0) {{
                risksHtml = '<div class="row">';
                groupRisks.forEach(risk => {{
                    const severity = risk.severity || risk.severity_level || 'Medium';
                    const badgeColor = {{
                        'Critical': 'danger',
                        'High': 'warning',
                        'Medium': 'info',
                        'Low': 'success'
                    }}[severity] || 'secondary';
                    const icon = {{
                        'Critical': 'exclamation-triangle',
                        'High': 'exclamation-circle',
                        'Medium': 'info-circle',
                        'Low': 'check-circle'
                    }}[severity] || 'info-circle';
                    
                    risksHtml += `
                        <div class="col-12 mb-2">
                            <div class="card border-${{badgeColor}}">
                                <div class="card-body p-2">
                                    <span class="badge bg-${{badgeColor}} me-2">
                                        <i class="fas fa-${{icon}}"></i> ${{escapeHtml(severity)}}
                                    </span>
                                    <strong>${{escapeHtml(risk.type || risk.title || 'Unknown Risk')}}</strong>
                                    ${{risk.description ? '<p class="mb-0 mt-1 small text-muted">' + escapeHtml(risk.description.substring(0, 150)) + '</p>' : ''}}
                                </div>
                            </div>
                        </div>
                    `;
                }});
                risksHtml += '</div>';
            }} else {{
                risksHtml = '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No risks found for this group.</div>';
            }}
            
            // Build modern modal content (escapeHtml prevents XSS from LDAP data)
            document.getElementById('objectDetailModalLabel').innerHTML = `
                <i class="fas fa-users-cog text-primary"></i> Group Details: <strong>${{escapeHtml(groupName)}}</strong>
            `;
            document.getElementById('objectDetailContent').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-primary text-white">
                                <i class="fas fa-info-circle"></i> Group Information
                            </div>
                            <div class="card-body">
                                <table class="table table-sm table-borderless mb-0">
                                    <tr>
                                        <td width="40%"><strong><i class="fas fa-tag"></i> Group Name:</strong></td>
                                        <td>${{groupName}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-users"></i> Member Count:</strong></td>
                                        <td><span class="badge bg-info">${{memberCount}}</span></td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-shield-alt"></i> Privileged:</strong></td>
                                        <td>${{isPrivileged ? '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle"></i> Yes</span>' : '<span class="badge bg-success"><i class="fas fa-check"></i> No</span>'}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-exclamation-triangle"></i> Risk Count:</strong></td>
                                        <td><span class="badge bg-${{groupRisks.length > 0 ? 'warning' : 'success'}}">${{groupRisks.length}}</span></td>
                                    </tr>
                                    ${{group.description ? `<tr><td><strong><i class="fas fa-align-left"></i> Description:</strong></td><td>${{group.description}}</td></tr>` : ''}}
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-secondary text-white">
                                <i class="fas fa-chart-bar"></i> Statistics
                            </div>
                            <div class="card-body">
                                <div class="row text-center">
                                    <div class="col-6">
                                        <h4 class="text-primary">${{memberCount}}</h4>
                                        <small class="text-muted">Members</small>
                                    </div>
                                    <div class="col-6">
                                        <h4 class="text-${{groupRisks.length > 0 ? 'warning' : 'success'}}">${{groupRisks.length}}</h4>
                                        <small class="text-muted">Risks</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <i class="fas fa-users"></i> Members (${{memberCount}})
                            </div>
                            <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                                ${{membersHtml}}
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-${{groupRisks.length > 0 ? 'warning' : 'success'}} text-white">
                                <i class="fas fa-exclamation-triangle"></i> Security Risks (${{groupRisks.length}})
                            </div>
                            <div class="card-body">
                                ${{risksHtml}}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            const modal = new bootstrap.Modal(document.getElementById('objectDetailModal'));
            modal.show();
        }}
        
        function showComputerDetails(computerName) {{
            const computer = directoryData.allComputers.find(c => c.name === computerName);
            if (!computer) return;
            
            const compRisks = directoryData.allRisks.filter(r => r.affected_object === computerName);
            
            // Format last logon
            let lastLogon = 'N/A';
            if (computer.lastLogonTimestamp) {{
                try {{
                    const logonDate = new Date(computer.lastLogonTimestamp);
                    lastLogon = logonDate.toLocaleString();
                }} catch(e) {{
                    lastLogon = computer.lastLogonTimestamp;
                }}
            }}
            
            // Check if domain controller
            const isDC = computer.operatingSystem && (
                computer.operatingSystem.toUpperCase().includes('SERVER') ||
                computer.operatingSystem.toUpperCase().includes('DOMAIN CONTROLLER')
            );
            
            // Build risks HTML with modern styling
            let risksHtml = '';
            if (compRisks.length > 0) {{
                risksHtml = '<div class="row">';
                compRisks.forEach(risk => {{
                    const severity = risk.severity || risk.severity_level || 'Medium';
                    const badgeColor = {{
                        'Critical': 'danger',
                        'High': 'warning',
                        'Medium': 'info',
                        'Low': 'success'
                    }}[severity] || 'secondary';
                    const icon = {{
                        'Critical': 'exclamation-triangle',
                        'High': 'exclamation-circle',
                        'Medium': 'info-circle',
                        'Low': 'check-circle'
                    }}[severity] || 'info-circle';
                    
                    risksHtml += `
                        <div class="col-12 mb-2">
                            <div class="card border-${{badgeColor}}">
                                <div class="card-body p-2">
                                    <span class="badge bg-${{badgeColor}} me-2">
                                        <i class="fas fa-${{icon}}"></i> ${{escapeHtml(severity)}}
                                    </span>
                                    <strong>${{escapeHtml(risk.type || risk.title || 'Unknown Risk')}}</strong>
                                    ${{risk.description ? '<p class="mb-0 mt-1 small text-muted">' + escapeHtml(risk.description.substring(0, 150)) + '</p>' : ''}}
                                </div>
                            </div>
                        </div>
                    `;
                }});
                risksHtml += '</div>';
            }} else {{
                risksHtml = '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No risks found for this computer.</div>';
            }}
            
            // Build modern modal content (escapeHtml prevents XSS from LDAP data)
            document.getElementById('objectDetailModalLabel').innerHTML = `
                <i class="fas fa-server text-primary"></i> Computer Details: <strong>${{escapeHtml(computerName)}}</strong>
            `;
            document.getElementById('objectDetailContent').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-primary text-white">
                                <i class="fas fa-info-circle"></i> Computer Information
                            </div>
                            <div class="card-body">
                                <table class="table table-sm table-borderless mb-0">
                                    <tr>
                                        <td width="40%"><strong><i class="fas fa-server"></i> Computer Name:</strong></td>
                                        <td>${{escapeHtml(computerName)}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-desktop"></i> Operating System:</strong></td>
                                        <td>${{escapeHtml(computer.operatingSystem || 'Unknown')}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-clock"></i> Last Logon:</strong></td>
                                        <td>${{escapeHtml(lastLogon)}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-building"></i> Type:</strong></td>
                                        <td>${{isDC ? '<span class="badge bg-danger"><i class="fas fa-shield-alt"></i> Domain Controller</span>' : '<span class="badge bg-info"><i class="fas fa-desktop"></i> Workstation</span>'}}</td>
                                    </tr>
                                    <tr>
                                        <td><strong><i class="fas fa-exclamation-triangle"></i> Risk Count:</strong></td>
                                        <td><span class="badge bg-${{compRisks.length > 0 ? 'warning' : 'success'}}">${{compRisks.length}}</span></td>
                                    </tr>
                                    ${{computer.description ? `<tr><td><strong><i class="fas fa-align-left"></i> Description:</strong></td><td>${{escapeHtml(computer.description)}}</td></tr>` : ''}}
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header bg-secondary text-white">
                                <i class="fas fa-chart-bar"></i> Statistics
                            </div>
                            <div class="card-body">
                                <div class="row text-center">
                                    <div class="col-12">
                                        <h4 class="text-${{compRisks.length > 0 ? 'warning' : 'success'}}">${{compRisks.length}}</h4>
                                        <small class="text-muted">Security Risks</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-${{compRisks.length > 0 ? 'warning' : 'success'}} text-white">
                                <i class="fas fa-exclamation-triangle"></i> Security Risks (${{compRisks.length}})
                            </div>
                            <div class="card-body">
                                ${{risksHtml}}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            const modal = new bootstrap.Modal(document.getElementById('objectDetailModal'));
            modal.show();
        }}
        
        // Excel Export Function (exports full data from directoryTableRows for paginated tables)
        function exportToExcel(type) {{
            let table, filename, useFullData = false;
            const timestamp = new Date().toISOString().slice(0,19).replace(/:/g, '-');
            
            if (type === 'users') {{
                table = document.getElementById('usersTable');
                filename = `AtilKurt_Users_${{timestamp}}.csv`;
            }} else if (type === 'groups') {{
                table = document.getElementById('groupsTable');
                filename = `AtilKurt_Groups_${{timestamp}}.csv`;
            }} else if (type === 'computers') {{
                table = document.getElementById('computersTable');
                filename = `AtilKurt_Computers_${{timestamp}}.csv`;
            }} else {{
                return;
            }}
            
            if (!table) return;
            
            // Use full rows from pagination cache (filtered or full)
            let rowsToExport = table.querySelectorAll('tbody tr');
            if (window.directoryTableRows && window.directoryTableRows[type]) {{
                const dataRows = window.directoryTableFiltered && window.directoryTableFiltered[type]
                    ? window.directoryTableFiltered[type] : window.directoryTableRows[type];
                if (dataRows && dataRows.length > 0) {{
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = '<table><tbody>' + dataRows.join('') + '</tbody></table>';
                    rowsToExport = tempDiv.querySelectorAll('tbody tr');
                    useFullData = true;
                }}
            }}
            
            const headerRow = table.querySelector('thead tr');
            const rows = useFullData && headerRow
                ? [headerRow, ...Array.from(rowsToExport)] : Array.from(table.querySelectorAll('tr'));
            let csv = [];
            
            rows.forEach((row, index) => {{
                const cols = row.querySelectorAll('td, th');
                const rowData = [];
                
                // Special handling for groups table - include all members
                if (type === 'groups' && row.querySelector('td')) {{
                    const groupMembers = row.getAttribute('data-group-members');
                    let membersText = '';
                    if (groupMembers) {{
                        try {{
                            const members = JSON.parse(groupMembers);
                            // Join members with semicolon for Excel compatibility
                            membersText = members.join('; ');
                        }} catch(e) {{
                            membersText = '';
                        }}
                    }}
                    
                    cols.forEach((col, colIndex) => {{
                        let text = col.textContent.trim();
                        text = text.replace(/View Details/g, '').trim();
                        
                        // Replace Members column (index 1) with full member list
                        if (colIndex === 1 && membersText) {{
                            text = membersText;
                        }}
                        
                        rowData.push('"' + text.replace(/"/g, '""') + '"');
                    }});
                }} else {{
                    // Normal export for users and computers
                    cols.forEach(col => {{
                        // Remove button text and icons, get clean text
                        let text = col.textContent.trim();
                        // Remove action buttons text
                        text = text.replace(/View Details/g, '').trim();
                        rowData.push('"' + text.replace(/"/g, '""') + '"');
                    }});
                }}
                
                if (rowData.length > 0) {{
                    csv.push(rowData.join(','));
                }}
            }});
            
            // Create download
            const csvContent = csv.join('\\n');
            const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', filename);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }}
        if (typeof window !== 'undefined') window.exportToExcel = exportToExcel;
        
        // Generic table export function
        function exportTableToExcel(tableId, tableName) {{
            const table = document.getElementById(tableId);
            if (!table) {{
                console.warn('Table not found:', tableId);
                return;
            }}
            
            const timestamp = new Date().toISOString().slice(0,19).replace(/:/g, '-');
            const filename = `AtilKurt_${{tableName}}_${{timestamp}}.csv`;
            
            let csv = [];
            const headerRow = Array.from(table.querySelectorAll('thead tr'))[0];
            if (headerRow) {{
                const headerCols = headerRow.querySelectorAll('th');
                const headerData = [];
                headerCols.forEach(col => {{
                    let text = (col.textContent || '').trim();
                    text = text.replace(/\\s*<i class="fas fa-sort[^"]*"><\\/i>/g, '').trim();
                    headerData.push('"' + String(text).replace(/"/g, '""') + '"');
                }});
                if (headerData.length) csv.push(headerData.join(','));
            }} else {{
                csv.push('"' + String(tableName).replace(/"/g, '""') + '"');
            }}
            
            // Get all data based on table type
            let dataRows = [];
            
            // Check for paginated tables and export all data
            if (tableId === 'passwordIssuesPreviewTable' && window.passwordIssuesData) {{
                window.passwordIssuesData.forEach(detail => {{
                    dataRows.push([
                        detail.username || 'Unknown',
                        detail.issue || 'N/A',
                        (detail.days !== null && detail.days !== undefined) ? detail.days.toString() : 'N/A'
                    ]);
                }});
            }} else if (tableId === 'passwordIssuesFullTable' && window.passwordIssuesFullData) {{
                window.passwordIssuesFullData.forEach(detail => {{
                    dataRows.push([
                        detail.username || 'Unknown',
                        detail.issue || 'N/A',
                        (detail.days !== null && detail.days !== undefined) ? detail.days.toString() : 'N/A'
                    ]);
                }});
            }} else if (tableId === 'recentlyCreatedTable' && window.recentlyCreatedData) {{
                window.recentlyCreatedData.forEach(detail => {{
                    dataRows.push([
                        detail.username || 'Unknown',
                        detail.days_ago || 0,
                        detail.period || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'recentlyGroupChangedTable' && window.recentlyGroupChangedData) {{
                window.recentlyGroupChangedData.forEach(detail => {{
                    dataRows.push([
                        detail.username || 'Unknown',
                        detail.period || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'domainAdminTable' && window.domainAdminData) {{
                window.domainAdminData.forEach(member => {{
                    dataRows.push([
                        member.username || 'Unknown',
                        (member.groups || []).join(', '),
                        member.accountCreated || 'N/A',
                        member.groupAdded || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'enterpriseAdminTable' && window.enterpriseAdminData) {{
                window.enterpriseAdminData.forEach(member => {{
                    dataRows.push([
                        member.username || 'Unknown',
                        (member.groups || []).join(', '),
                        member.accountCreated || 'N/A',
                        member.groupAdded || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'schemaAdminTable' && window.schemaAdminData) {{
                window.schemaAdminData.forEach(member => {{
                    dataRows.push([
                        member.username || 'Unknown',
                        (member.groups || []).join(', '),
                        member.accountCreated || 'N/A',
                        member.groupAdded || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'disabledAccountsTable' && window.disabledAccountsData) {{
                window.disabledAccountsData.forEach(account => {{
                    dataRows.push([
                        account.username || 'Unknown',
                        account.displayName || 'N/A',
                        account.disabledTime || 'N/A'
                    ]);
                }});
            }} else if (tableId === 'lockedAccountsTable' && window.lockedAccountsData) {{
                window.lockedAccountsData.forEach(account => {{
                    dataRows.push([
                        account.username || 'Unknown',
                        account.displayName || 'N/A',
                        account.lockedTime || 'N/A'
                    ]);
                }});
            }} else {{
                // Regular table export - get visible rows
                const visibleRows = Array.from(table.querySelectorAll('tbody tr'));
                visibleRows.forEach(row => {{
                    const cols = row.querySelectorAll('td');
                    const rowData = [];
                    cols.forEach(col => {{
                        let text = col.textContent.trim();
                        text = text.replace(/<[^>]+>/g, '').trim();
                        rowData.push(text);
                    }});
                    if (rowData.length > 0) {{
                        dataRows.push(rowData);
                    }}
                }});
            }}
            
            // Add data rows to CSV
            dataRows.forEach(rowData => {{
                const csvRow = rowData.map(cell => '"' + String(cell).replace(/"/g, '""') + '"').join(',');
                csv.push(csvRow);
            }});
            
            // Create download
            const csvContent = csv.join('\\n');
            const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', filename);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }}
        if (typeof window !== 'undefined') window.exportTableToExcel = exportTableToExcel;
        
        // Table sorting function
        let sortDirection = {{}};
        function sortTable(tableId, columnIndex) {{
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            const rows = Array.from(tbody.querySelectorAll('tr'));
            if (rows.length === 0) return;
            
            // Initialize sort direction for this table/column
            const sortKey = `${{tableId}}_${{columnIndex}}`;
            if (!sortDirection[sortKey]) {{
                sortDirection[sortKey] = 'asc';
            }} else {{
                sortDirection[sortKey] = sortDirection[sortKey] === 'asc' ? 'desc' : 'asc';
            }}
            
            const direction = sortDirection[sortKey];
            
            // Sort rows
            rows.sort((a, b) => {{
                const aText = a.cells[columnIndex] ? a.cells[columnIndex].textContent.trim() : '';
                const bText = b.cells[columnIndex] ? b.cells[columnIndex].textContent.trim() : '';
                
                // Try to parse as number
                const aNum = parseFloat(aText.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bText.replace(/[^0-9.-]/g, ''));
                
                let comparison = 0;
                if (!isNaN(aNum) && !isNaN(bNum)) {{
                    comparison = aNum - bNum;
                }} else {{
                    comparison = aText.localeCompare(bText, undefined, {{ numeric: true, sensitivity: 'base' }});
                }}
                
                return direction === 'asc' ? comparison : -comparison;
            }});
            
            // Clear tbody and re-append sorted rows
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
            
            // Update sort icons
            const headers = table.querySelectorAll('thead th');
            headers.forEach((header, index) => {{
                const icon = header.querySelector('i');
                if (icon) {{
                    if (index === columnIndex) {{
                        icon.className = direction === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
                    }} else {{
                        icon.className = 'fas fa-sort';
                    }}
                }}
            }});
        }}
        </script>
        """

    def _generate_users_table_rows(self, users_data, users, risks):
        """Generate table rows for users."""
        rows = []
        for user_data in users_data:
            username = user_data['sAMAccountName']
            groups_display = ', '.join(user_data['groups'][:3])
            if user_data['group_count'] > 3:
                groups_display += f" (+{user_data['group_count'] - 3} more)"
            
            # Status badges
            status_badges = []
            if user_data.get('isDisabled'):
                status_badges.append('<span class="badge bg-secondary">Disabled</span>')
            if user_data.get('isLocked'):
                status_badges.append('<span class="badge bg-danger">Locked</span>')
            if not status_badges:
                status_badges.append('<span class="badge bg-success">Active</span>')
            status_display = ' '.join(status_badges)
            
            # Last logon display
            last_logon_display = user_data.get('lastLogon', 'N/A')
            days_since_logon = user_data.get('daysSinceLastLogon')
            if days_since_logon is not None:
                if days_since_logon >= 90:
                    last_logon_display += f' <span class="badge bg-danger">{days_since_logon}d</span>'
                elif days_since_logon >= 30:
                    last_logon_display += f' <span class="badge bg-warning">{days_since_logon}d</span>'
            
            # Account age display
            account_age_display = user_data.get('accountAge', 'N/A')
            
            # Admin groups display
            admin_groups_display = []
            if user_data.get('domainAdminGroups'):
                admin_groups_display.append(f'<span class="badge bg-danger">DA ({len(user_data["domainAdminGroups"])})</span>')
            if user_data.get('enterpriseAdminGroups'):
                admin_groups_display.append(f'<span class="badge bg-danger">EA ({len(user_data["enterpriseAdminGroups"])})</span>')
            if user_data.get('schemaAdminGroups'):
                admin_groups_display.append(f'<span class="badge bg-danger">SA ({len(user_data["schemaAdminGroups"])})</span>')
            admin_groups_html = ' '.join(admin_groups_display) if admin_groups_display else '<span class="text-muted">-</span>'
            
            # SPN display
            spn_display = '<span class="badge bg-warning">Yes</span>' if user_data.get('hasSPN') else '<span class="text-muted">No</span>'
            
            # Service account display
            service_account_display = '<span class="badge bg-info">Yes</span>' if user_data.get('isServiceAccount') else '<span class="text-muted">No</span>'
            if user_data.get('isServiceWithPwdNeverExpires'):
                service_account_display += ' <span class="badge bg-danger">Pwd Never Expires</span>'
            
            privileged_badge = '<span class="badge bg-danger">Yes</span>' if user_data['adminCount'] else '<span class="badge bg-success">No</span>'
            risk_badge = f'<span class="badge bg-warning">{user_data["risk_count"]}</span>' if user_data['risk_count'] > 0 else '<span class="badge bg-success">0</span>'
            critical_badge = f'<span class="badge bg-danger">{user_data["critical_risks"]}</span>' if user_data['critical_risks'] > 0 else '<span class="badge bg-secondary">0</span>'
            
            rows.append(f"""
            <tr>
                <td><strong>{username}</strong></td>
                <td>{user_data['displayName']}</td>
                <td>{status_display}</td>
                <td><small>{last_logon_display}</small></td>
                <td><small>{account_age_display}</small></td>
                <td>{admin_groups_html}</td>
                <td>{spn_display}</td>
                <td>{service_account_display}</td>
                <td><small>{groups_display}</small></td>
                <td>{risk_badge}</td>
                <td>{critical_badge}</td>
                <td>{privileged_badge}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="showUserDetails('{username}')">
                        <i class="fas fa-eye"></i> View Details
                    </button>
                </td>
            </tr>
            """)
        return rows

    def _generate_groups_table_rows(self, groups_data, groups, risks):
        """Generate table rows for groups."""
        rows = []
        for group_data in groups_data:
            group_name = group_data['name']
            members_list = group_data.get('members', [])
            member_count = group_data['member_count']
            
            # Display members
            if member_count > 0 and len(members_list) > 0:
                members_display = f"{member_count} member(s): {', '.join(members_list[:5])}"
                if member_count > 5:
                    members_display += f" (+{member_count - 5} more)"
            else:
                members_display = "0 members"
            
            privileged_badge = '<span class="badge bg-danger">Yes</span>' if group_data['is_privileged'] else '<span class="badge bg-success">No</span>'
            risk_badge = f'<span class="badge bg-warning">{group_data["risk_count"]}</span>' if group_data['risk_count'] > 0 else '<span class="badge bg-success">0</span>'
            critical_badge = f'<span class="badge bg-danger">{group_data["critical_risks"]}</span>' if group_data['critical_risks'] > 0 else '<span class="badge bg-secondary">0</span>'
            
            # Store members list in data attribute for Excel export
            members_json = json.dumps(members_list, default=str)
            
            rows.append(f"""
            <tr data-group-members='{members_json}'>
                <td><strong>{group_name}</strong></td>
                <td><small>{members_display}</small></td>
                <td>{risk_badge}</td>
                <td>{critical_badge}</td>
                <td>{privileged_badge}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="showGroupDetails('{group_name}')">
                        <i class="fas fa-eye"></i> View Details
                    </button>
                </td>
            </tr>
            """)
        return rows

    def _generate_computers_table_rows(self, computers_data, computers, risks):
        """Generate table rows for computers."""
        rows = []
        for comp_data in computers_data:
            comp_name = comp_data['name']
            risk_badge = f'<span class="badge bg-warning">{comp_data["risk_count"]}</span>' if comp_data['risk_count'] > 0 else '<span class="badge bg-success">0</span>'
            critical_badge = f'<span class="badge bg-danger">{comp_data["critical_risks"]}</span>' if comp_data['critical_risks'] > 0 else '<span class="badge bg-secondary">0</span>'
            
            rows.append(f"""
            <tr>
                <td><strong>{comp_name}</strong></td>
                <td><small>{comp_data['operatingSystem']}</small></td>
                <td>{risk_badge}</td>
                <td>{critical_badge}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="showComputerDetails('{comp_name}')">
                        <i class="fas fa-eye"></i> View Details
                    </button>
                </td>
            </tr>
            """)
        return rows
