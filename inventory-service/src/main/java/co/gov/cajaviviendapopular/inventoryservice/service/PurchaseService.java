package co.gov.cajaviviendapopular.inventoryservice.service;

import co.gov.cajaviviendapopular.inventoryservice.exception.ProductQuantityNotAvailableException;
import co.gov.cajaviviendapopular.inventoryservice.model.Product;
import co.gov.cajaviviendapopular.inventoryservice.model.Purchase;
import co.gov.cajaviviendapopular.inventoryservice.repository.ProductRepository;
import co.gov.cajaviviendapopular.inventoryservice.repository.PurchaseRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

@Service
public class PurchaseService {

    protected PurchaseRepository purchaseRepository;

    protected ProductRepository productRepository;
    public PurchaseService(PurchaseRepository purchaseRepository,
                           ProductRepository productRepository) {
        this.purchaseRepository = purchaseRepository;
        this.productRepository = productRepository;
    }

    public Purchase createNewPurchase(Purchase purchase) {
        Optional<Product> optionalProduct = this.productRepository.findById(purchase.getProduct().getName());
        if (optionalProduct.isPresent()) {
            Product product = optionalProduct.get();
            if (purchase.getQuantity() > product.getQuantity()) {
                throw new ProductQuantityNotAvailableException(String.format("Productos solicitados {%d}, Productos disponibles {%d}",
                        purchase.getQuantity(), product.getQuantity()));
            } else {
                product.setQuantity(product.getQuantity() - purchase.getQuantity());
                purchase.setProduct(product);
                purchase.setTotalPrice(new BigDecimal(purchase.getQuantity().intValue()*product.getPrice().doubleValue()));
                return this.purchaseRepository.save(purchase);
            }
        }else{
            throw new EntityNotFoundException("Product no encontrado con id" + purchase.getProduct().getName());
        }
    }

    public List<Purchase> getAll() {
        return this.purchaseRepository.findAll();

    }
}