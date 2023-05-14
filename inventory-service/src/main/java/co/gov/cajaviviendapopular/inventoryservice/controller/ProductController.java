package co.gov.cajaviviendapopular.inventoryservice.controller;

import co.gov.cajaviviendapopular.inventoryservice.model.Product;
import co.gov.cajaviviendapopular.inventoryservice.service.ProductService;
import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.repository.query.Param;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("products")
public class ProductController {

    private ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }
    @GetMapping
    public ResponseEntity<List<Product>> findAllProducts() {
        return ResponseEntity.ok(productService.findAll());
    }

    @PostMapping
    public ResponseEntity<Product> saveProduct(@RequestBody Product product) {
        if (this.productService.findById(product) == null) {
            log.info("product is null");
            return ResponseEntity.ok(this.productService.saveProduct(product));
        } else {
            throw new EntityExistsException();
        }
    }

    @RequestMapping("/{name}")
    @PutMapping(params = "name")
    public ResponseEntity<Product> updateProduct(@RequestBody Product product, @PathVariable("name") String name) {
        log.info("Updating product {}", name);
        if (this.productService.findById(product) == null) {
            log.info("product is null");
            throw new EntityNotFoundException();
        } else {
            return ResponseEntity.ok(this.productService.saveProduct(product));

        }
    }
    @GetMapping
    @RequestMapping("/available")
    public ResponseEntity<List<Product>>findAvailableProducts(){
        return ResponseEntity.ok(productService.findAvailableProducts());
    }

}