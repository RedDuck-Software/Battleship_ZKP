import React from 'react';
import './App.css';
import ZokratesProvider from './contexts/ZokratesContext';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <ZokratesProvider>
        </ZokratesProvider>
      </header>
    </div>
  );
}

export default App;
