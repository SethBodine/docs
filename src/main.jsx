import React from 'react';
import ReactDOM from 'react-dom/client';
import App, { ErrorBoundary } from './App.jsx';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary label="DocScan hit an unexpected error.">
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
