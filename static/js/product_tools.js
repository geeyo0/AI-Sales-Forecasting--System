(() => {
    const start = () => {
        if (window.foodcastProductToolsReady) return;
        window.foodcastProductToolsReady = true;
        const confirmDialog = document.getElementById('action-confirm');
        const no = document.getElementById('confirm-no');
        const yes = document.getElementById('confirm-yes');
        const manager = document.getElementById('unit-manager');
        const picker = document.getElementById('unit-picker');
        const addProductDialog = document.getElementById('add-product-dialog');
        let pending = null;
        let origin = null;

        function ask(message, action) {
            if (!confirmDialog || confirmDialog.open) return;
            origin = document.activeElement;
            pending = action;
            document.getElementById('confirm-message').textContent = message;
            confirmDialog.showModal();
            no.focus();
        }
        no?.addEventListener('click', () => confirmDialog.close());
        yes?.addEventListener('click', () => {
            const action = pending;
            pending = null;
            confirmDialog.close();
            action?.();
        });
        confirmDialog?.addEventListener('close', () => {
            pending = null;
            if (origin?.isConnected) origin.focus();
        });

        document.addEventListener('submit', event => {
            const form = event.target;
            if (!(form instanceof HTMLFormElement)) return;
            if (form.dataset.confirmed === 'yes') {
                delete form.dataset.confirmed;
                return;
            }
            const path = new URL(form.action, location.href).pathname;
            if (path.endsWith('/logout')) {
                event.preventDefault();
                const submitter = event.submitter;
                ask('Do you want to sign out?', () => {
                    form.dataset.confirmed = 'yes';
                    submitter ? form.requestSubmit(submitter) : form.requestSubmit();
                });
            }
        });

        document.addEventListener('click', event => {
            const pick = event.target.closest('[data-pick-unit]');
            if (pick) {
                document.getElementById('chosen-unit').value = pick.dataset.pickUnit;
                document.getElementById('unit-choice').textContent = pick.dataset.pickUnit;
                picker.open = false;
                picker.querySelector('summary').focus();
            }

            const remove = event.target.closest('[data-delete-unit]');
            if (remove) {
                ask(`Delete the unit “${remove.dataset.unitName}”?`, () => {
                    const form = document.getElementById('delete-unit-form');
                    form.elements.unit_id.value = remove.dataset.deleteUnit;
                    form.requestSubmit();
                });
            }

            if (event.target.closest('[data-open-units]')) {
                if (picker) picker.open = false;
                manager?.showModal();
                document.getElementById('new-unit')?.focus();
            }
            if (event.target.closest('[data-close-units]')) manager?.close();
            if (picker && !picker.contains(event.target)) picker.open = false;

            if (event.target.closest('[data-open-add-product]')) {
                if (picker) picker.open = false;
                addProductDialog?.showModal();
            }
            if (event.target.closest('[data-close-add-product]')) addProductDialog?.close();

            const deleteProduct = event.target.closest('[data-delete-product]');
            if (deleteProduct) {
                ask(`Delete “${deleteProduct.dataset.productName}”? This cannot be undone.`, () => {
                    const form = document.getElementById('delete-product-form');
                    form.action = `/business/products/${deleteProduct.dataset.deleteProduct}/delete`;
                    form.requestSubmit();
                });
            }
        });

        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && picker?.open) {
                picker.open = false;
                picker.querySelector('summary').focus();
            }
        });

       const selectAll = document.getElementById('select-all-products');
const productCheckboxes = Array.from(
    document.querySelectorAll('.product-row-select')
);
const bulkEditButton = document.getElementById(
    'bulk-edit-products'
);
const bulkDeleteButton = document.getElementById(
    'bulk-delete-products'
);
const selectedCount = document.getElementById(
    'selected-products-count'
);
const bulkDeleteForm = document.getElementById(
    'bulk-delete-products-form'
);
const bulkDeleteInputs = document.getElementById(
    'bulk-delete-product-inputs'
);

function getSelectedProductRows() {
    return productCheckboxes
        .filter(checkbox => checkbox.checked)
        .map(checkbox => checkbox.closest('[data-product-row]'))
        .filter(Boolean);
}

function updateBulkActions() {
    const selectedRows = getSelectedProductRows();
    const count = selectedRows.length;

    if (selectedCount) {
        selectedCount.textContent = `${count} selected`;
    }

    if (bulkEditButton) {
    bulkEditButton.disabled = count === 0;
    bulkEditButton.title = count > 1
        ? `Edit ${count} selected products`
        : 'Edit selected product';
}

    if (bulkDeleteButton) {
        bulkDeleteButton.disabled = count === 0;
    }

    if (selectAll) {
        selectAll.checked =
            productCheckboxes.length > 0
            && count === productCheckboxes.length;

        selectAll.indeterminate =
            count > 0
            && count < productCheckboxes.length;
    }
}

selectAll?.addEventListener('change', () => {
    productCheckboxes.forEach(checkbox => {
        checkbox.checked = selectAll.checked;
    });

    updateBulkActions();
});

productCheckboxes.forEach(checkbox => {
    checkbox.addEventListener('change', updateBulkActions);
});

bulkEditButton?.addEventListener('click', () => {
    const selectedRows = getSelectedProductRows();

    if (selectedRows.length === 0) {
        return;
    }

    const parameters = new URLSearchParams();

    selectedRows.forEach(row => {
        parameters.append(
            'product_id',
            row.dataset.productId
        );
    });

    window.location.href =
        `/business/products/bulk-edit?${parameters.toString()}`;
});sss

bulkDeleteButton?.addEventListener('click', () => {
    const selectedRows = getSelectedProductRows();

    if (
        selectedRows.length === 0
        || !bulkDeleteForm
        || !bulkDeleteInputs
    ) {
        return;
    }

    ask(
        `Delete ${selectedRows.length} selected product(s)? `
        + 'This cannot be undone.',
        () => {
            bulkDeleteInputs.replaceChildren();

            selectedRows.forEach(row => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'product_id';
                input.value = row.dataset.productId;
                bulkDeleteInputs.appendChild(input);
            });

            bulkDeleteForm.requestSubmit();
        }
    );
});

updateBulkActions();
        // Combined search + filter + sort + pagination over the products table.
        const rows = Array.from(document.querySelectorAll('[data-product-row]'));
        if (rows.length) {
            const PAGE_SIZE = 6;
            const topSearch = document.getElementById('product_search');
            const inlineSearch = document.getElementById('inline_product_search');
            const clearTopSearch = document.getElementById('clear-product-search');
            const categoryFilter = document.getElementById('category_filter');
            const statusFilter = document.getElementById('status_filter');
            const sortBy = document.getElementById('sort_by');
            const emptyMessage = document.getElementById('product-search-empty');
            const summary = document.getElementById('products-pagination-summary');
            const buttonsWrap = document.getElementById('products-pagination-buttons');
            let currentPage = 1;

            function syncSearchInputs(value) {
                if (topSearch) topSearch.value = value;
                if (inlineSearch) inlineSearch.value = value;
                if (clearTopSearch) clearTopSearch.hidden = value.trim().length === 0;
            }

            function render() {
                const text = (inlineSearch?.value || topSearch?.value || '').trim().toLowerCase();
                const category = categoryFilter?.value || '';
                const status = statusFilter?.value || '';
                const sort = sortBy?.value || 'name';

                let visible = rows.filter(row => {
                    const matchesText = row.dataset.productName.includes(text);
                    const matchesCategory = !category || row.dataset.category === category;
                    const matchesStatus = !status || row.dataset.status === status;
                    return matchesText && matchesCategory && matchesStatus;
                });

                visible.sort((a, b) => {
                    if (sort === 'price-asc') return parseFloat(a.dataset.price) - parseFloat(b.dataset.price);
                    if (sort === 'price-desc') return parseFloat(b.dataset.price) - parseFloat(a.dataset.price);
                    if (sort === 'stock-asc') return parseFloat(a.dataset.stock) - parseFloat(b.dataset.stock);
                    return a.dataset.productName.localeCompare(b.dataset.productName);
                });

                rows.forEach(row => { row.hidden = true; });

                const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
                currentPage = Math.min(currentPage, totalPages);
                const start = (currentPage - 1) * PAGE_SIZE;
                const pageRows = visible.slice(start, start + PAGE_SIZE);

                pageRows.forEach((row, index) => {
                    row.hidden = false;
                    row.parentElement.appendChild(row); // keep sorted order in the DOM
                    void index;
                });

                if (emptyMessage) emptyMessage.hidden = visible.length > 0;

                if (summary) {
                    summary.textContent = visible.length
                        ? `Showing ${start + 1}–${Math.min(start + PAGE_SIZE, visible.length)} of ${visible.length} products`
                        : 'No products to show';
                }

                if (buttonsWrap) {
                    buttonsWrap.innerHTML = '';

                    const prev = document.createElement('button');
                    prev.type = 'button';
                    prev.className = 'pagination-btn';
                    prev.textContent = '<';
                    prev.disabled = currentPage === 1;
                    prev.addEventListener('click', () => { currentPage -= 1; render(); });
                    buttonsWrap.appendChild(prev);

                    for (let page = 1; page <= totalPages; page += 1) {
                        const button = document.createElement('button');
                        button.type = 'button';
                        button.className = 'pagination-btn' + (page === currentPage ? ' active' : '');
                        button.textContent = String(page);
                        button.addEventListener('click', () => { currentPage = page; render(); });
                        buttonsWrap.appendChild(button);
                    }

                    const next = document.createElement('button');
                    next.type = 'button';
                    next.className = 'pagination-btn';
                    next.textContent = '>';
                    next.disabled = currentPage === totalPages;
                    next.addEventListener('click', () => { currentPage += 1; render(); });
                    buttonsWrap.appendChild(next);
                }
            }

            topSearch?.addEventListener('input', () => {
                syncSearchInputs(topSearch.value);
                currentPage = 1;
                render();
            });
            inlineSearch?.addEventListener('input', () => {
                syncSearchInputs(inlineSearch.value);
                currentPage = 1;
                render();
            });
            clearTopSearch?.addEventListener('click', () => {
                syncSearchInputs('');
                currentPage = 1;
                render();
                topSearch?.focus();
            });
            categoryFilter?.addEventListener('change', () => { currentPage = 1; render(); });
            statusFilter?.addEventListener('change', () => { currentPage = 1; render(); });
            sortBy?.addEventListener('change', () => { currentPage = 1; render(); });

            render();
        }
    };
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', start) : start();
})();