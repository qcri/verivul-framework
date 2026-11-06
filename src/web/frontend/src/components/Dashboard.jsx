import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../utils/api';
import Stats from './Stats';
import ResourcePanel from './ResourcePanel';

const PAGE_SIZE = 50;

const Dashboard = () => {
  const [snippets, setSnippets]         = useState([]);
  const [models, setModels]             = useState([]);
  const [languages, setLanguages]       = useState([]);
  const [loading, setLoading]           = useState(true);
  const [loadingMore, setLoadingMore]   = useState(false);
  const [hasMore, setHasMore]           = useState(true);
  const [error, setError]               = useState(null);
  const [skip, setSkip]                 = useState(0);
  const [lastRefresh, setLastRefresh]   = useState(new Date());
  const intervalRef                     = useRef(null);

  const [filters, setFilters] = useState({
    status: '',
    label: '',
    model: '',
    language: '',
    sort: 'updated_at',
    sortDesc: true,
  });

  const buildParams = useCallback((extraSkip = 0) => {
    const p = {
      skip: extraSkip, limit: PAGE_SIZE, type: 'GENERATED',
      sort_by: filters.sort, sort_desc: filters.sortDesc,
    };
    if (filters.status)   p.status   = filters.status;
    if (filters.label)    p.label    = filters.label;
    if (filters.model)    p.model    = filters.model;
    if (filters.language) p.language = filters.language;
    return p;
  }, [filters]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [snippetsData, modelsData, langsData] = await Promise.all([
        api.getSnippets(buildParams(0)),
        api.getModels(),
        api.getLanguages(),
      ]);
      const list = Array.isArray(snippetsData) ? snippetsData : [];
      setSnippets(list);
      setSkip(PAGE_SIZE);
      setHasMore(list.length === PAGE_SIZE);
      setModels(Array.isArray(modelsData?.models) ? modelsData.models : []);
      setLanguages(Array.isArray(langsData?.languages) ? langsData.languages : []);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Error fetching data:', err);
      setError('Failed to load data. Please try again later.');
    } finally {
      setLoading(false);
    }
  }, [buildParams]);

  useEffect(() => {
    fetchData();
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(fetchData, 30000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchData]);

  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore) return;
    setLoadingMore(true);
    try {
      const more = await api.getSnippets(buildParams(skip));
      const list = Array.isArray(more) ? more : [];
      if (list.length < PAGE_SIZE) setHasMore(false);
      setSnippets(prev => [...prev, ...list]);
      setSkip(prev => prev + PAGE_SIZE);
    } catch (err) {
      console.error('Error loading more snippets:', err);
    } finally {
      setLoadingMore(false);
    }
  }, [skip, hasMore, loadingMore, buildParams]);

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
  };

  const getStatusColor = (status) => ({
    'COMPILATION_SUCCESS':  'bg-blue-200 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    'COMPILATION_FAILED':   'bg-red-200 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'VERIFICATION_SUCCESS': 'bg-green-200 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    'VERIFICATION_ERROR':   'bg-red-200 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'VERIFICATION_TIMEOUT': 'bg-orange-200 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
    'GENERATION_SUCCESS':   'bg-indigo-200 text-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300',
    'GENERATION_FAILED':    'bg-red-200 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'GROUND_TRUTH':         'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-300',
  }[status] || 'bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-300');

  const getLabelColor = (label) => ({
    'SAFE':       'bg-green-300 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    'VULNERABLE': 'bg-red-300 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'UNKNOWN':    'bg-slate-300 text-slate-800 dark:bg-slate-700 dark:text-slate-300',
  }[label] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300');

  const selectCls = 'w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 px-3 py-2 text-sm';

  return (
    <div className="space-y-6">
      <ResourcePanel />
      <Stats />

      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold text-gray-800 dark:text-white">Code Snippets</h2>
            <div className="flex items-center gap-3">
              <span className="text-sm text-gray-500 dark:text-gray-400">
                Last updated: {format(lastRefresh, 'HH:mm:ss')}
                <span className="ml-2 text-green-600 dark:text-green-400">● Auto-refresh 30s</span>
              </span>
              <button
                onClick={fetchData}
                className="px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                Refresh
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
              <select name="status" value={filters.status} onChange={handleFilterChange} className={selectCls}>
                <option value="">All Statuses</option>
                <option value="COMPILATION_SUCCESS">Compilation Success</option>
                <option value="COMPILATION_FAILED">Compilation Failed</option>
                <option value="VERIFICATION_SUCCESS">Verification Success</option>
                <option value="VERIFICATION_TIMEOUT">Verification Timeout</option>
                <option value="VERIFICATION_ERROR">Verification Error</option>
                <option value="GENERATION_SUCCESS">Generation Success</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Label</label>
              <select name="label" value={filters.label} onChange={handleFilterChange} className={selectCls}>
                <option value="">All Labels</option>
                <option value="SAFE">Safe</option>
                <option value="VULNERABLE">Vulnerable</option>
                <option value="UNKNOWN">Unknown</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Model</label>
              <select name="model" value={filters.model} onChange={handleFilterChange} className={selectCls}>
                <option value="">All Models</option>
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Language</label>
              <select name="language" value={filters.language} onChange={handleFilterChange} className={selectCls}>
                <option value="">All Languages</option>
                {languages.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Sort By</label>
              <div className="flex">
                <select name="sort" value={filters.sort} onChange={handleFilterChange}
                  className="w-full rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 px-3 py-2 text-sm">
                  <option value="updated_at">Updated At</option>
                  <option value="created_at">Created At</option>
                  <option value="attempt_count">Attempt Count</option>
                </select>
                <button
                  onClick={() => setFilters(prev => ({ ...prev, sortDesc: !prev.sortDesc }))}
                  className="px-3 py-2 border border-l-0 border-gray-300 dark:border-gray-600 rounded-r-md bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300"
                >
                  {filters.sortDesc ? '↓' : '↑'}
                </button>
              </div>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center items-center py-12">
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-500" />
          </div>
        ) : error ? (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">{error}</div>
        ) : (
          <>
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
              <div className="overflow-x-auto overflow-y-auto max-h-[70vh]">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0 z-10">
                    <tr>
                      {['Model','Status','Label','UUID','Seed UUID','Updated','CWEs','Attempts'].map(h => (
                        <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {snippets.length === 0 ? (
                      <tr>
                        <td colSpan="8" className="px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
                          No code snippets found with the selected filters.
                        </td>
                      </tr>
                    ) : snippets.map(s => (
                      <tr key={s.uuid} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">{s.generation_model}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(s.status)}`}>{s.status}</span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {s.label
                            ? <span className={`px-2 py-1 rounded-full text-xs font-medium ${getLabelColor(s.label)}`}>{s.label}</span>
                            : <span className="text-gray-400 dark:text-gray-500">—</span>}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-600 dark:text-blue-400 font-medium">
                          <Link to={`/snippets/${s.uuid}`} className="hover:text-blue-800 dark:hover:text-blue-300 font-mono">{s.uuid.substring(0, 8)}…</Link>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 font-mono">{s.seed_uuid.substring(0, 8)}…</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{format(new Date(s.updated_at), 'MMM d HH:mm')}</td>
                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                          <div className="flex flex-wrap gap-1">
                            {s.cwes && s.cwes.length > 0
                              ? s.cwes.map(cwe => (
                                  <span key={cwe} className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400">{cwe}</span>
                                ))
                              : <span className="text-gray-300 dark:text-gray-600">—</span>}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{s.attempt_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {hasMore && (
              <div className="mt-4 flex justify-center">
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="px-5 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loadingMore ? (
                    <span className="flex items-center gap-2">
                      <span className="inline-block w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                      Loading…
                    </span>
                  ) : `Load more (showing ${snippets.length})`}
                </button>
              </div>
            )}
            {!hasMore && snippets.length > 0 && (
              <p className="text-center text-sm text-gray-400 dark:text-gray-500 py-3">All {snippets.length} snippets loaded.</p>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
