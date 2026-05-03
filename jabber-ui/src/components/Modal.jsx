import React, { useEffect } from 'react';
import { X, AlertCircle, CheckCircle2, HelpCircle, AlertTriangle } from 'lucide-react';

export default function Modal({
  isOpen,
  onClose,
  title,
  message,
  type = 'info', // info, success, warning, error, confirm
  onConfirm,
  confirmText = 'OK',
  cancelText = 'Cancel'
}) {
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const getIcon = () => {
    switch (type) {
      case 'success': return <CheckCircle2 className="modal__icon modal__icon--success" size={24} />;
      case 'warning': return <AlertTriangle className="modal__icon modal__icon--warning" size={24} />;
      case 'error': return <AlertCircle className="modal__icon modal__icon--error" size={24} />;
      case 'confirm': return <HelpCircle className="modal__icon modal__icon--confirm" size={24} />;
      default: return <AlertCircle className="modal__icon modal__icon--info" size={24} />;
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-container animate-scale-in" onClick={e => e.stopPropagation()}>
        <div className="modal__header">
          <div className="modal__icon-wrap">
            {getIcon()}
          </div>
          <h2 className="modal__title">{title}</h2>
          <button className="modal__close" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        
        <div className="modal__body">
          <p className="modal__message">{message}</p>
        </div>

        <div className="modal__footer">
          {type === 'confirm' ? (
            <>
              <button className="modal__btn modal__btn--secondary" onClick={onClose}>
                {cancelText}
              </button>
              <button className="modal__btn modal__btn--primary" onClick={() => { onConfirm(); onClose(); }}>
                {confirmText}
              </button>
            </>
          ) : (
            <button className="modal__btn modal__btn--primary" onClick={onClose}>
              {confirmText}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
