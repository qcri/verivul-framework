import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import CodeSnippetView from './components/CodeSnippetView';
import Pairs from './components/Pairs';
import Seeds from './components/Seeds';

function App() {
  return (
    <ThemeProvider>
      <Router>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
          <Navbar />
          <main className="container mx-auto px-4 py-8">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/pairs" element={<Pairs />} />
              <Route path="/seeds" element={<Seeds />} />
              <Route path="/snippets/:uuid" element={<CodeSnippetView />} />
            </Routes>
          </main>
        </div>
      </Router>
    </ThemeProvider>
  );
}

export default App;
