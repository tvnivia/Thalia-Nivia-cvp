package co.gov.cajaviviendapopular.inventoryservice.service;

import co.gov.cajaviviendapopular.inventoryservice.model.Product;
import co.gov.cajaviviendapopular.inventoryservice.repository.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProductService {

    private ProductRepository productRepository;

    private ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> findAll() {
        return this.productRepository.findAll();
    }

    public Product findById(Product product) {
        Optional<Product> optionalProduct = this.productRepository.findById(product.getName());
        if (optionalProduct.isPresent()) {
            return optionalProduct.get();
        } else {
            return null;
        }
    }

    public Product saveProduct(Product product) {
        return this.productRepository.save(product);
    }

    public List<Product> findAvailableProducts() {
        return this.productRepository
                .findAll()
                .stream()
                .filter(product -> product.getQuantity()>0)
                .toList();
    }
}