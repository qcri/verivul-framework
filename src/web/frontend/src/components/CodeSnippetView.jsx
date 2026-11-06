import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { format } from 'date-fns';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import api from '../utils/api';

const CodeSnippetView = () => {
  const { uuid } = useParams();
  const [snippet, setSnippet] = useState(null);
  const [children, setChildren] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('code');

  const [seedSnippet, setSeedSnippet] = useState(null);
  const [seedLoading, setSeedLoading] = useState(false);
  const [seedError, setSeedError] = useState(null);

  useEffect(() => {
    const fetchSnippet = async () => {
      setLoading(true);
      setError(null);
      setSnippet(null);
      setChildren([]);
      setSeedSnippet(null);
      setSeedError(null);
      try {
        const data = await api.getSnippet(uuid);
        setSnippet(data);
        const childrenData = await api.getChildSnippets(uuid);
        setChildren(childrenData);
      } catch (err) {
        console.error('Error fetching snippet:', err);
        setError('Failed to load snippet data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    fetchSnippet();
  }, [uuid]);

  useEffect(() => {
    const fetchSeedSnippet = async () => {
      if (snippet && snippet.seed_uuid) {
        if (snippet.seed_uuid === snippet.uuid) {
          setSeedSnippet(snippet);
          return;
        }
        setSeedLoading(true);
        setSeedError(null);
        try {
          const seedData = await api.getSnippet(snippet.seed_uuid);
          setSeedSnippet(seedData);
        } catch (err) {
          console.error('Error fetching seed snippet:', err);
          setSeedError('Failed to load seed snippet data.');
        } finally {
          setSeedLoading(false);
        }
      } else {
        setSeedSnippet(null);
      }
    };
    if (!loading && snippet) fetchSeedSnippet();
  }, [snippet, loading]);

  const getStatusColor = (status) => ({
    'COMPILATION_SUCCESS': 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    'FAILED_COMPILATION':  'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'VERIFICATION_SUCCESS':'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    'VERIFICATION_TIMEOUT':'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
    'FIXING_SUCCESS':      'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300',
  }[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300');

  const getLabelColor = (label) => ({
    'SAFE':       'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    'VULNERABLE': 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    'UNKNOWN':    'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  }[label] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300');

  const tabCls = (tab) =>
    activeTab === tab
      ? 'border-primary-500 text-primary-600 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm'
      : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-500 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm';

  const infoBox = 'bg-gray-50 dark:bg-gray-700 p-4 rounded-lg';
  const infoLabel = 'text-sm font-medium text-gray-500 dark:text-gray-400 mb-1';
  const infoValue = 'font-medium text-gray-800 dark:text-gray-100';

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-6"></div>
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2 mb-4"></div>
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3 mb-4"></div>
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
            ))}
          </div>
          <div className="mt-6 h-40 bg-gray-200 dark:bg-gray-700 rounded"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">
          {error}
        </div>
        <div className="mt-4">
          <Link to="/" className="text-primary-600 hover:text-primary-800">&larr; Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  if (!snippet) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 text-center">
        <p className="text-gray-500 dark:text-gray-400">Snippet not found or still loading.</p>
        <div className="mt-4">
          <Link to="/" className="text-primary-600 hover:text-primary-800">&larr; Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="mb-6">
          <Link to="/" className="text-primary-600 hover:text-primary-800">&larr; Back to Dashboard</Link>
        </div>

        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-2">Code Snippet</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">UUID: {snippet.uuid}</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className={infoBox}>
            <h3 className={infoLabel}>Status</h3>
            <div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(snippet.status)}`}>
                {snippet.status}
              </span>
            </div>
          </div>

          <div className={infoBox}>
            <h3 className={infoLabel}>Label</h3>
            <div>
              {snippet.label ? (
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getLabelColor(snippet.label)}`}>
                  {snippet.label}
                </span>
              ) : (
                <span className="text-gray-400 dark:text-gray-500">Not labeled</span>
              )}
            </div>
          </div>

          <div className={infoBox}>
            <h3 className={infoLabel}>Model</h3>
            <div className={infoValue}>{snippet.generation_model || 'N/A'}</div>
          </div>

          {snippet.seed_uuid && (
            <div className={infoBox}>
              <h3 className={infoLabel}>Seed UUID</h3>
              <Link to={`/snippets/${snippet.seed_uuid}`} className="text-primary-600 hover:text-primary-800 font-medium">
                {snippet.seed_uuid}
              </Link>
            </div>
          )}

          <div className={infoBox}>
            <h3 className={infoLabel}>Created At</h3>
            <div className={infoValue}>{format(new Date(snippet.created_at), 'MMM d, yyyy HH:mm:ss')}</div>
          </div>

          <div className={infoBox}>
            <h3 className={infoLabel}>Last Updated</h3>
            <div className={infoValue}>{format(new Date(snippet.updated_at), 'MMM d, yyyy HH:mm:ss')}</div>
          </div>

          {snippet.parent_uuid && (
            <div className={infoBox}>
              <h3 className={infoLabel}>Parent Snippet</h3>
              <Link to={`/snippets/${snippet.parent_uuid}`} className="text-primary-600 hover:text-primary-800 font-medium">
                {snippet.parent_uuid.substring(0, 8)}...
              </Link>
            </div>
          )}

          <div className={infoBox}>
            <h3 className={infoLabel}>Attempt Count</h3>
            <div className={infoValue}>{snippet.attempt_count}</div>
          </div>

          {snippet.language && (
            <div className={infoBox}>
              <h3 className={infoLabel}>Language</h3>
              <div className={infoValue}>{snippet.language}</div>
            </div>
          )}

          <div className={infoBox}>
            <h3 className={infoLabel + ' mb-2'}>CWEs (target mapping)</h3>
            {snippet.cwes && snippet.cwes.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {snippet.cwes.map((cwe) => (
                  <span key={cwe} className="px-2 py-1 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400">
                    {cwe}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-gray-400 dark:text-gray-500 text-sm">—</span>
            )}
          </div>

          <div className={infoBox}>
            <h3 className={infoLabel + ' mb-2'}>ESBMC CWEs</h3>
            {snippet.esbmc_cwes && snippet.esbmc_cwes.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {snippet.esbmc_cwes.map((cwe) => (
                  <span key={cwe} className={'px-2 py-1 rounded-full text-xs font-medium ' + (snippet.cwes?.includes(cwe)
                    ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400'
                    : 'bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-400')}>
                    {cwe}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-gray-400 dark:text-gray-500 text-sm">—</span>
            )}
          </div>
        </div>

        <div className="border-t border-gray-200 dark:border-gray-700 pt-6">
          <div className="mb-4">
            <div className="border-b border-gray-200 dark:border-gray-700">
              <nav className="-mb-px flex space-x-8 overflow-x-auto">
                <button onClick={() => setActiveTab('code')} className={tabCls('code')}>Code</button>
                {snippet.seed_uuid && snippet.seed_uuid !== snippet.uuid && (
                  <button onClick={() => setActiveTab('seed_code')} className={tabCls('seed_code')}>Seed Code</button>
                )}
                {snippet.seed_uuid && snippet.seed_uuid !== snippet.uuid && seedSnippet?.slice_code && (
                  <button onClick={() => setActiveTab('seed_slice')} className={tabCls('seed_slice')}>Seed Slice</button>
                )}
                {snippet.compilation_log && (
                  <button onClick={() => setActiveTab('compilation_log')} className={tabCls('compilation_log')}>Compilation Logs</button>
                )}
                {snippet.install_command && (
                  <button onClick={() => setActiveTab('installation')} className={tabCls('installation')}>Installation Commands</button>
                )}
                {snippet.esbmc_log && (
                  <button onClick={() => setActiveTab('esbmc_log')} className={tabCls('esbmc_log')}>Verification Log</button>
                )}
                {snippet.verification_meta?.confirmation && (
                  <button onClick={() => setActiveTab('sanitizer')} className={tabCls('sanitizer')}>Sanitizer</button>
                )}
                {snippet.witness && (
                  <button onClick={() => setActiveTab('witness')} className={tabCls('witness')}>Witness</button>
                )}
                {snippet.info && (
                  <button onClick={() => setActiveTab('info')} className={tabCls('info')}>Additional Information</button>
                )}
                {children.length > 0 && (
                  <button onClick={() => setActiveTab('children')} className={tabCls('children')}>
                    Child Snippets ({children.length})
                  </button>
                )}
              </nav>
            </div>
          </div>

          <div className="mt-6">
            {activeTab === 'code' && (
              <SyntaxHighlighter
                language={snippet.language || 'cpp'}
                style={atomOneDark}
                showLineNumbers={true}
                customStyle={{ borderRadius: '0.375rem', maxHeight: '600px', overflowY: 'auto' }}
                wrapLines={true}
                lineProps={{ style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap' } }}
              >
                {snippet.code || '// No code available'}
              </SyntaxHighlighter>
            )}

            {activeTab === 'seed_code' && snippet.seed_uuid && (
              <div>
                {seedLoading && (
                  <div className="animate-pulse">
                    <div className="h-40 bg-gray-200 dark:bg-gray-700 rounded"></div>
                  </div>
                )}
                {seedError && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">
                    {seedError}
                  </div>
                )}
                {!seedLoading && !seedError && seedSnippet && (
                  <>
                    <div className="mb-2 text-sm text-gray-600 dark:text-gray-300">
                      Displaying code for seed snippet:{' '}
                      <Link to={`/snippets/${seedSnippet.uuid}`} className="text-primary-600 hover:text-primary-800 font-medium">
                        {seedSnippet.uuid.substring(0, 8)}...
                      </Link>
                    </div>
                    <SyntaxHighlighter
                      language={seedSnippet.language || snippet.language || 'cpp'}
                      style={atomOneDark}
                      showLineNumbers={true}
                      customStyle={{ borderRadius: '0.375rem', maxHeight: '600px', overflowY: 'auto' }}
                      wrapLines={true}
                      lineProps={{ style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap' } }}
                    >
                      {seedSnippet.code || '// No code available for seed snippet'}
                    </SyntaxHighlighter>
                  </>
                )}
                {!seedLoading && !seedError && !seedSnippet && (
                  <p className="text-gray-500 dark:text-gray-400">Seed snippet data is not available.</p>
                )}
              </div>
            )}

            {activeTab === 'seed_slice' && seedSnippet?.slice_code && (
              <div>
                <div className="mb-2 text-sm text-gray-600 dark:text-gray-300">
                  Slice code for seed snippet:{' '}
                  <Link to={`/snippets/${seedSnippet.uuid}`} className="text-primary-600 hover:text-primary-800 font-medium">
                    {seedSnippet.uuid.substring(0, 8)}...
                  </Link>
                </div>
                <SyntaxHighlighter
                  language={seedSnippet.language || snippet.language || 'cpp'}
                  style={atomOneDark}
                  showLineNumbers={true}
                  customStyle={{ borderRadius: '0.375rem', maxHeight: '600px', overflowY: 'auto' }}
                  wrapLines={true}
                  lineProps={{ style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap' } }}
                >
                  {seedSnippet.slice_code}
                </SyntaxHighlighter>
              </div>
            )}

            {activeTab === 'compilation_log' && snippet.compilation_log && (
              <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto whitespace-pre-wrap text-sm max-h-[600px]">
                {snippet.compilation_log}
              </pre>
            )}

            {activeTab === 'installation' && snippet.install_command && (
              <SyntaxHighlighter
                language="bash"
                style={atomOneDark}
                showLineNumbers={true}
                customStyle={{ borderRadius: '0.375rem', maxHeight: '400px', overflowY: 'auto' }}
                wrapLines={true}
                lineProps={{ style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap' } }}
              >
                {snippet.install_command}
              </SyntaxHighlighter>
            )}

            {activeTab === 'esbmc_log' && snippet.esbmc_log && (
              <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto whitespace-pre-wrap text-sm max-h-[600px]">
                {snippet.esbmc_log}
              </pre>
            )}

            {activeTab === 'sanitizer' && snippet.verification_meta?.confirmation && (() => {
              const c = snippet.verification_meta.confirmation;
              const f = c.finding;
              return (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    {snippet.reproduced && (
                      <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                        snippet.reproduced === 'REPRODUCED' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                        : snippet.reproduced === 'PENDING' ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-400'
                        : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'}`}>{snippet.reproduced}</span>
                    )}
                    <span className="px-2 py-1 rounded-full text-xs font-medium bg-indigo-100 dark:bg-indigo-900/30 text-indigo-800 dark:text-indigo-300">{c.result}</span>
                    {(snippet.sanitizer_cwes || []).map(cwe => (
                      <span key={cwe} className="px-2 py-1 rounded-full text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">{cwe}</span>
                    ))}
                    {c.env_dependent && <span className="px-2 py-1 rounded-full text-xs bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-400">environment-dependent</span>}
                    {f?.kind && <span className="text-gray-600 dark:text-gray-300">{f.kind}{f.function ? ` in ${f.function}` : ''}{f.line ? ` (line ${f.line})` : ''}</span>}
                    {c.runs != null && <span className="text-gray-500 dark:text-gray-400">{c.runs} runs{c.elapsed_s != null ? `, ${Number(c.elapsed_s).toFixed(1)}s` : ''}</span>}
                  </div>
                  {c.sanitizer_flags && (
                    <div className="text-xs text-gray-500 dark:text-gray-400 break-all">Flags: <code>{c.sanitizer_flags}</code></div>
                  )}
                  {f?.report ? (
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto whitespace-pre-wrap text-sm max-h-[600px]">{f.report}</pre>
                  ) : (
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {c.error ? `Runner error: ${c.error}` : 'No sanitizer report: no run of the program triggered a finding.'}
                    </div>
                  )}
                  {f?.input_b64 && (
                    <div className="text-xs text-gray-500 dark:text-gray-400 break-all">
                      <a
                        href={`data:application/octet-stream;base64,${f.input_b64}`}
                        download={`poc-${snippet.uuid.substring(0, 8)}.bin`}
                        className="mr-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 border border-indigo-200 dark:border-indigo-700 rounded px-2 py-1"
                      >
                        Download input
                      </a>
                      {f.input_as_path ? 'Sent as a file whose path is on stdin. ' : 'Sent on stdin. '}
                      Base64: <code>{f.input_b64.length > 600 ? `${f.input_b64.slice(0, 600)}…` : f.input_b64}</code>
                    </div>
                  )}
                </div>
              );
            })()}

            {activeTab === 'witness' && snippet.witness && (
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">GraphML violation witness produced by ESBMC</span>
                  <a
                    href={`data:application/xml;charset=utf-8,${encodeURIComponent(snippet.witness)}`}
                    download={`witness-${snippet.uuid.substring(0, 8)}.graphml`}
                    className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 border border-indigo-200 dark:border-indigo-700 rounded px-2 py-1"
                  >
                    Download .graphml
                  </a>
                </div>
                <SyntaxHighlighter
                  language="xml"
                  style={atomOneDark}
                  showLineNumbers={true}
                  customStyle={{ borderRadius: '0.375rem', maxHeight: '600px', overflowY: 'auto' }}
                  wrapLines={true}
                  lineProps={{ style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap' } }}
                >
                  {snippet.witness}
                </SyntaxHighlighter>
              </div>
            )}

            {activeTab === 'info' && snippet.info && (
              <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto whitespace-pre-wrap text-sm max-h-[600px]">
                {snippet.info}
              </pre>
            )}

            {activeTab === 'children' && (
              <div>
                {children.length === 0 ? (
                  <p className="text-gray-500 dark:text-gray-400">No child snippets found.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                      <thead className="bg-gray-50 dark:bg-gray-700">
                        <tr>
                          {['UUID', 'Status', 'Label', 'Language', 'Created At'].map(h => (
                            <th key={h} scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        {children.map((child) => (
                          <tr key={child.uuid} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-primary-600 font-medium">
                              <Link to={`/snippets/${child.uuid}`}>{child.uuid.substring(0, 8)}...</Link>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(child.status)}`}>
                                {child.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">
                              {child.label ? (
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getLabelColor(child.label)}`}>
                                  {child.label}
                                </span>
                              ) : (
                                <span className="text-gray-400 dark:text-gray-500">-</span>
                              )}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                              {child.language || 'N/A'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                              {format(new Date(child.created_at), 'MMM d, yyyy HH:mm')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CodeSnippetView;
