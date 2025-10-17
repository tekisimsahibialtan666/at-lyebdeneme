(function () {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('imageInput');
  const previewGrid = document.getElementById('previewGrid');

  if (!dropzone || !fileInput || !previewGrid) {
    return;
  }

  const renderPreviews = (files) => {
    previewGrid.innerHTML = '';
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (event) => {
        const container = document.createElement('div');
        container.className = 'preview-item';
        const image = document.createElement('img');
        image.src = event.target.result;
        image.alt = file.name;
        const caption = document.createElement('span');
        caption.textContent = file.name;
        container.appendChild(image);
        container.appendChild(caption);
        previewGrid.appendChild(container);
      };
      reader.readAsDataURL(file);
    });
  };

  const handleFiles = (files) => {
    if (!files.length) return;
    const dataTransfer = new DataTransfer();
    Array.from(files).forEach((file) => dataTransfer.items.add(file));
    fileInput.files = dataTransfer.files;
    renderPreviews(fileInput.files);
  };

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('dragover');
    if (event.dataTransfer?.files?.length) {
      handleFiles(event.dataTransfer.files);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      renderPreviews(fileInput.files);
    } else {
      previewGrid.innerHTML = '';
    }
  });
})();
