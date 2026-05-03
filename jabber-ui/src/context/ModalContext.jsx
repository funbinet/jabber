import React, { createContext, useContext, useState } from 'react';
import Modal from '../components/Modal.jsx';

const ModalContext = createContext();

export function ModalProvider({ children }) {
  const [modalConfig, setModalConfig] = useState({
    isOpen: false,
    title: '',
    message: '',
    type: 'info',
    onConfirm: () => {},
    confirmText: 'OK',
    cancelText: 'Cancel'
  });

  const showAlert = (title, message, type = 'info') => {
    setModalConfig({
      isOpen: true,
      title,
      message,
      type,
      confirmText: 'OK'
    });
  };

  const showConfirm = (title, message, onConfirm, confirmText = 'Yes, Proceed', cancelText = 'Cancel') => {
    setModalConfig({
      isOpen: true,
      title,
      message,
      type: 'confirm',
      onConfirm,
      confirmText,
      cancelText
    });
  };

  const closeModal = () => {
    setModalConfig(prev => ({ ...prev, isOpen: false }));
  };

  return (
    <ModalContext.Provider value={{ showAlert, showConfirm, closeModal }}>
      {children}
      <Modal 
        {...modalConfig} 
        onClose={closeModal}
      />
    </ModalContext.Provider>
  );
}

export const useModal = () => useContext(ModalContext);
